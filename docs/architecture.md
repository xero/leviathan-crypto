<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### Architecture

Overview of Leviathan Crypto's architecture, twelve independent WASM modules unified by a misuse-resistant TypeScript API: bitsliced ciphers (Serpent, XChaCha20, AES), ML-KEM, lattice and hash-based signatures (ML-DSA, SLH-DSA, hybrid composites), hashing (SHA-2, SHA-3, BLAKE3), Merkle transparency, forward-secret ratchet, and Fortuna CSPRNG.

> ### Table of Contents
>
> - [Architectural overview](#architectural-overview)
> - [Scope](#scope)
> - [Repository Structure](#repository-structure)
>     - [AssemblyScript layer](#assemblyscript-layer)
>     - [TypeScript layer](#typescript-layer)
>     - [Tests](#tests)
>     - [Project files](#project-files)
> - [Build and CI](#build-and-ci)
>     - [Build Scripts](#build-scripts)
>     - [Build Pipeline](#build-pipeline)
>     - [CI/CD](#cicd)
> - [WebAssembly Modules](#webassembly-modules)
>     - [WebAssembly is the deployment vehicle](#webassembly-is-the-deployment-vehicle)
>     - [Twelve Independent WASM Modules](#twelve-independent-wasm-modules)
>     - [Buffer Layouts](#buffer-layouts)
> - [init() API](#init-api)
> - [Public API Classes](#public-api-classes)
> - [Module Relationships](#module-relationships)
> - [NPM Package](#npm-package)
> - [Test Suite](#test-suite)
> - [Security](#security)
>     - [Correctness Contract](#correctness-contract)
>     - [Cryptanalytic margin](#cryptanalytic-margin)
>     - [Constant-time at the algorithm level](#constant-time-at-the-algorithm-level)
>     - [Implementation discipline](#implementation-discipline)
>     - [Threat model](#threat-model)
>     - [Defended attacks](#defended-attacks)
>     - [Where defense ends](#where-defense-ends)
>     - [The honest comparison](#the-honest-comparison)
>     - [Known Limitations](#known-limitations)
> - [Cross-References](#cross-references)

---

## Architectural overview

**Zero runtime dependencies.** No NPM graph to audit. No supply chain attack surface.

**Tree-shakeable.** Import only what you use. Subpath exports let bundlers exclude everything else.

**Side-effect free.** Nothing runs on import. [`init()`](./init.md) is explicit and asynchronous.

**Cipher Triptych.** Leviathan provides three ciphers. The implementations all use a round structure that operates as a bitsliced Boolean circuit, implemented with register-only logic and no S-box lookup tables. Each compiles to an independent, v128 SIMD-optimized WebAssembly module with isolated linear memory, which prevents cross-module memory access by design. Every operation zeroes key material on exit, including on failure.

**[Serpent-256](./serpent_reference.md): maximum paranoia.** 32 rounds of eight different 4-bit S-boxes, each bitsliced as a Boolean circuit with no table lookups. An ouroboros devouring every bit, in every block, through every round.

**[XChaCha20-Poly1305](./chacha_reference.md): precise elegance.** 20 rounds of add-rotate-XOR alternating column and diagonal quarter-rounds, choreography without S-boxes or cache-timing leakage. A dance closing with Poly1305's unconditional forgery bound.

**[AES-256-GCM-SIV](./aes_reference.md): industry standard, sharpened.** 14 rounds bitsliced into Boolean gates with tower-field S-box with no table lookups. A fresh POLYVAL key per nonce leaves GHASH-key recovery with no target.

**Beneath the cipher suites sit three hash primitive families:** [`sha2`](./sha2.md) (SHA-224/256/384/512 and SHA-512/224/256, with HMAC and HKDF variants), [`sha3`](./sha3.md) (SHA3-224/256/384/512 and SHAKE128/256), and [`blake3`](./blake3.md) (default-mode hash, keyed_hash, derive_key, and an unbounded XOF reader). The round permutations are constant-time by algorithm design: pure bit operations with no S-box lookups and no data-dependent branches. `sha2` powers the seal layer's HKDF key derivation and Serpent's HMAC authentication. `sha3` is the Keccak sponge ML-KEM and ML-DSA rely on internally. The SHA-512 truncation variants (SHA-512/224, SHA-512/256) and SHA-224 support the twelve HashML-DSA pre-hash functions. `blake3` is the SIMD-only tree-mode hash for transcripts, content-addressed storage, and KDF work; it ships a `HashFn` compatible with the Fortuna substrate.

**Above the cipher suites sits a cipher-agnostic [AEAD layer](./aead.md):** `Seal`, `SealStream`, `OpenStream`, and `SealStreamPool`. Each takes a `CipherSuite` at construction, and the seal layer handles key derivation, nonce management, and authentication. `Seal` covers one-shot encryption for data that fits in memory. `SealStream` and `OpenStream` handle chunked data too large to buffer. WASM instances are single-threaded by design, so `SealStreamPool` distributes chunks across Web Workers to reach multi-core throughput. Any authentication failure kills the pool. Pending operations reject, workers zero their keys and terminate, and the master synchronously zeroes its copies. No retry, no partial results. All four share one wire format. A `Seal` blob is structurally a single-chunk `SealStream` output, and `OpenStream` decrypts it interchangeably.

**[ML-KEM](./mlkem.md): post-quantum handshake.** `MlKemSuite` is a fourth `CipherSuite` factory that wraps an ML-KEM parameter set (`MlKem512`, `MlKem768`, `MlKem1024`) around any of the three ciphers above. The result slots into `Seal`, `SealStream`, `OpenStream`, and `SealStreamPool` unchanged. Constant-time Fujisaki-Okamoto comparisons run inside the ML-KEM WASM module; the 32-byte shared secret derives directly from a SHA-3 output and never crosses the wire, so the leading-zero-trim timing leak that hit TLS-DH(E) (the Raccoon attack) has no structural analog here.

**Beside the AEAD layer sits a scheme-agnostic [signature layer](./signing.md):** `Sign`, `SignStream`, and `VerifyStream`. Each takes a `SignatureSuite` at construction, and the signature layer handles M' formatting, cross-protocol domain separation, hedged-by-default signing, and constant-time verification. `Sign` covers one-shot signing over inputs that fit in memory. `SignStream` and `VerifyStream` chunk through the prehash variants for anything larger. The shipping catalog covers ML-DSA, SLH-DSA, Ed25519 (pure and Ed25519ph), and ECDSA P-256, plus PQ-only and classical+PQ hybrid composites. Every suite speaks the same interface.

**[ML-DSA](./mldsa.md): lattice mainline.** `MlDsa44`, `MlDsa65`, and `MlDsa87` are FIPS 204 lattice-based signatures at NIST security categories 2, 3, and 5. Polynomial arithmetic, NTT, and rejection sampling are constant-time at the algorithm level. HashML-DSA covers the streaming path. The implementation lands every FIPS 204 §D.3 SUF-CMA check at runtime.

**[SLH-DSA](./slhdsa.md): assumption-diverse hedge.** `SlhDsa128f`, `SlhDsa192f`, and `SlhDsa256f` are FIPS 205 stateless hash-based signatures at NIST security categories 1, 3, and 5. Security rests on SHAKE preimage and collision resistance rather than any lattice or number-theoretic assumption, so a future lattice break against ML-DSA does not transfer. Three PQ-only hybrid composites (`MlDsa44SlhDsa128fSuite`, `MlDsa65SlhDsa192fSuite`, `MlDsa87SlhDsa256fSuite`) bind both PQ families to the same prehash digest under a unique `ctxDomain`. One break does not cascade.

**[Merkle log](./merkle): trust-anchored transparency.** `MerkleVerifier` and `MerkleLog` produce and verify C2SP-conformant signed checkpoints with RFC 9162 §2.1.3 / §2.1.4 inclusion and consistency proofs. Cosignatures use `Ed25519Suite` for Sigsum interop or `MlDsa44Suite` as the post-quantum default.

**[Fortuna](./fortuna.md): pluggable randomness.** It collects entropy from platform-specific sources (browser input events, timing jitter, Node.js process stats, plus `crypto.getRandomValues()` as a baseline), distributes it across 32 independent pools, and reseeds an internal generator built on a cipher-as-PRF construction. The generator key is replaced after every `get()` call, so state compromise at time T cannot reveal any output produced before T. The primitive pair is pluggable, mirroring `CipherSuite`'s extension-point pattern: any of the three ciphers above plugs into the generator, paired with either SHA-256 or SHA3-256 for hashing.

**Atop the seal layer sits the [ratchet module](./ratchet.md):** KDF primitives from Signal's Sparse Post-Quantum Ratchet (SPQR), the post-quantum extension of the Double Ratchet protocol. `ratchetInit` bootstraps the root and chain keys from an out-of-band shared secret. `KDFChain` advances a symmetric chain key and derives per-message keys with forward secrecy. `kemRatchetEncap` and `kemRatchetDecap` perform the ML-KEM ratchet step for post-compromise security. `SkippedKeyStore` caches message keys for out-of-order delivery; cached keys return through a transactional handle that commits on auth success and rolls back on failure, so a garbage ciphertext at a valid counter cannot consume the legitimate message's slot. The store also bounds memory and per-message HKDF work, so a malicious header with a high counter cannot force unbounded derivations. These are primitives, not a full session: state machines, message counters, header format, and epoch orchestration are application concerns. Consumers compose them with their own transport for forward-secret protocols whose needs outgrow one-shot AEAD.

**Outside the WASM-backed primitives ships a [utility tier](./utils.md).** No `init()` call required, every utility function works immediately on import. Pure-TypeScript encoding converters handle hex, base64, and the common byte-format round-trips. `wipe` and `xor` modules cover byte-buffer zeroing and exclusive OR logical operations. The `cte` module is the constant-time path. It carries its own dedicated WebAssembly binary that compiles synchronously, with a zero-copy v128 SIMD XOR-accumulate kernel. `constantTimeEqual` is the library's recommended path for any equality check on secret material.

**Discipline binds the layers.** Every cipher, hash, KEM, and signature scheme derives independently from its authoritative spec, never ported from another implementation. Known-answer test vectors come from spec authors, and cross-checks run against multiple independent reference implementations. The test suite covers unit tests at the primitive level plus end-to-end tests across three browser engines (Chromium, Firefox, WebKit) and Node.js. Detailed reference documentation ships at the [project wiki](https://github.com/xero/leviathan-crypto/wiki).

---

## Scope

**Primitives.** WASM algorithms with their TypeScript wrapper classes.

| Module                        | Algorithms                                                                                                                                                                        | TypeScript API                                                                                                                                                                                                                                                                                                                                                                                             |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`serpent`](./asm_serpent.md)     | Serpent-256 block cipher: ECB, CTR, CBC                                                                                                                                           | [`Serpent`](./serpent.md#serpent), [`SerpentCtr`](./serpent.md#serpentctr), [`SerpentCbc`](./serpent.md#serpentcbc), `SerpentGenerator` (Practical Cryptography §9.4 generator for `Fortuna`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| [`chacha20`](./asm_chacha.md)     | ChaCha20, Poly1305, ChaCha20-Poly1305, XChaCha20-Poly1305                                                                                                                         | [`ChaCha20`](./chacha20.md#chacha20), [`Poly1305`](./chacha20.md#poly1305), [`ChaCha20Poly1305`](./chacha20.md#chacha20poly1305), [`XChaCha20Poly1305`](./chacha20.md#xchacha20poly1305), [`ChaCha20Generator`](./chacha20.md#chacha20generator)                                                                                                                                                                                                                                                                                                                                                                                                                         |
| [`aes`](./asm_aes.md)             | AES-128/192/256 block cipher (FIPS 197), CBC, CTR, GCM, GCM-SIV (RFC 8452)                                                                                                        | [`AES`](./aes.md#aes), [`AESCbc`](./aes.md#aescbc), [`AESCtr`](./aes.md#aesctr), [`AESGCM`](./aes.md#aesgcm), [`AESGCMSIV`](./aes.md#aesgcmsiv), `AESGenerator` (Practical Cryptography §9.4 generator for `Fortuna`)                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| [`sha2`](./asm_sha2.md)           | SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, HMAC variants, HKDF variants                                                                                        | [`SHA224`](./sha2.md#sha224), [`SHA256`](./sha2.md#sha256), [`SHA384`](./sha2.md#sha384), [`SHA512`](./sha2.md#sha512), [`SHA512_224`](./sha2.md#sha512_224), [`SHA512_256`](./sha2.md#sha512_256), [`HMAC_SHA256`](./sha2.md#hmac_sha256), [`HMAC_SHA384`](./sha2.md#hmac_sha384), [`HMAC_SHA512`](./sha2.md#hmac_sha512), [`HKDF_SHA256`](./sha2.md#hkdf_sha256), [`HKDF_SHA512`](./sha2.md#hkdf_sha512)                                                                                                                                                                                                                                                                |
| [`sha3`](./asm_sha3.md)           | SHA3-224/256/384/512, SHAKE128, SHAKE256 (XOFs), cSHAKE128/256, KMAC128/256, KMACXOF128/256 (SP 800-185)                                                                            | [`SHA3_224`](./sha3.md#sha3_224), [`SHA3_256`](./sha3.md#sha3_256), [`SHA3_384`](./sha3.md#sha3_384), [`SHA3_512`](./sha3.md#sha3_512), [`SHAKE128`](./sha3.md#shake128), [`SHAKE256`](./sha3.md#shake256), [`SHA3_256Stream`](./sha3.md#sha3_256stream), [`SHA3_512Stream`](./sha3.md#sha3_512stream), [`SHAKE128Stream`](./sha3.md#shake128stream), [`SHAKE256Stream`](./sha3.md#shake256stream), [`CSHAKE128`](./kmac.md#cshake128), [`CSHAKE256`](./kmac.md#cshake256), [`KMAC128`](./kmac.md#kmac128), [`KMAC256`](./kmac.md#kmac256), [`KMACXOF128`](./kmac.md#kmacxof128), [`KMACXOF256`](./kmac.md#kmacxof256) |
| [`mlkem`](./asm_mlkem.md)         | ML-KEM polynomial arithmetic (FIPS 203): SIMD NTT, basemul, CBD, compression, FO comparisons                                                                                      | [`MlKem512`](./mlkem.md#parameter-sets), [`MlKem768`](./mlkem.md#parameter-sets), [`MlKem1024`](./mlkem.md#parameter-sets)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| [`mldsa`](./asm_mldsa.md)         | ML-DSA polynomial arithmetic (FIPS 204): SIMD NTT over q=8380417, rejection sampling, Power2Round, Decompose, MakeHint, HintBitPack/Unpack with §D.3 SUF-CMA checks, SampleInBall | [`MlDsa44`](./mldsa.md#mldsa-api), [`MlDsa65`](./mldsa.md#mldsa-api), [`MlDsa87`](./mldsa.md#mldsa-api) (pure ML-DSA and HashML-DSA across the twelve §5.4.1 pre-hash functions)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| [`slhdsa`](./asm_slhdsa.md)       | SLH-DSA stateless hash-based signing (FIPS 205): embedded Keccak permutation, F / H / T_ℓ / PRF / PRF_msg / H_msg tweakable hash family, ADRS encoding, WOTS+ / FORS / XMSS / hypertree composition | [`SlhDsa128f`](./slhdsa.md#slhdsa-api), [`SlhDsa192f`](./slhdsa.md#slhdsa-api), [`SlhDsa256f`](./slhdsa.md#slhdsa-api) (pure SLH-DSA and HashSLH-DSA across the twelve §10.2.2 pre-hash functions)                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| [`blake3`](./asm_blake3.md)       | BLAKE3 tree-mode hash family: v128-internal `compress` and lane-parallel `compress4` (§5.3 SIMD), §2.4 chunk machine, §2.5 tree assembly + root, §2.6 XOF, §2.3 keyed_hash and derive_key                  | [`BLAKE3`](./blake3.md#blake3), [`BLAKE3Stream`](./blake3.md#blake3stream), [`BLAKE3KeyedHash`](./blake3.md#blake3keyedhash), [`BLAKE3KeyedHashStream`](./blake3.md#blake3keyedhashstream), [`BLAKE3DeriveKey`](./blake3.md#blake3derivekey), [`BLAKE3DeriveKeyStream`](./blake3.md#blake3derivekeystream), [`BLAKE3OutputReader`](./blake3.md#blake3outputreader), [`BLAKE3Hash`](./blake3.md#blake3hash) (Fortuna HashFn)                                                                                                                                                                                                                                              |
| [`curve25519`](./asm_curve25519.md) | Ed25519 sign/verify (RFC 8032 §5.1) and X25519 keygen/DH (RFC 7748) over GF(2^255-19); embedded SHA-512 for the Ed25519 hash chain                                                | [`Ed25519`](./ed25519.md#ed25519-api) (pure + Ed25519ph), [`X25519`](./x25519.md#x25519-api) (Curve25519 Diffie-Hellman)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| [`p256`](./asm_p256.md)           | ECDSA sign/verify (FIPS 186-5 §6) over NIST P-256 (SP 800-186 §3.2.1.3); Renes-Costello-Batina complete addition; RFC 6979 deterministic + draft-irtf-cfrg-det-sigs-with-noise-05 hedged K-derivation; RFC 6979 §3.5 low-S enforcement on signer and verifier; embedded SHA-256 + HMAC-SHA-256 | [`EcdsaP256`](./ecdsa-p256.md#ecdsa-p256-api), [`pointDecompress`](./ecdsa-p256.md#point-decompression), DER codec helpers ([`ecdsaSignatureToDer`](./ecdsa-p256.md#ecprivatekey-der-codec), [`ecdsaSignatureFromDer`](./ecdsa-p256.md#ecprivatekey-der-codec), [`encodeEcPrivateKey`](./ecdsa-p256.md#ecprivatekey-der-codec), [`decodeEcPrivateKey`](./ecdsa-p256.md#ecprivatekey-der-codec))                                                                                                                                                                                                                                                                          |
| [`cte`](./asm_cte.md)             | Constant-time equality primitives: SIMD `compare` for the JS boundary, `@inline` source-level `ctEqual` for AS-internal use across other modules                                                                | [`constantTimeEqual`](./utils.md#constanttimeequal)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |


**Cipher Suites.** Composition of WASM modules into complete cipher packages.

| Suite                                                 | Composition                                | Use case                                        |
| ----------------------------------------------------- | ------------------------------------------ | ----------------------------------------------- |
| [`SerpentCipher`](./ciphersuite.md#serpentcipher)     | `serpent` + `sha2` (CBC+HMAC-SHA256)       | Authenticated encryption via STREAM             |
| [`XChaCha20Cipher`](./ciphersuite.md#xchacha20cipher) | `chacha20` (XChaCha20-Poly1305 AEAD)       | Streaming authenticated encryption              |
| [`AESGCMSIVCipher`](./ciphersuite.md#aesgcmsivcipher) | `aes` + `sha2` (AES-256-GCM-SIV, RFC 8452) | Nonce-misuse-resistant authenticated encryption |
| [`MlKemSuite`](./ciphersuite.md#mlkemsuite)           | `mlkem` + (any cipher)                     | Post-quantum key encapsulation                  |


**Signature Suites.** Composition of WASM modules into complete signing schemes.

| Suite                                                                                                                                                                               | Composition                                          | Use case                                                             |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- | -------------------------------------------------------------------- |
| [`MlDsa{44,65,87}Suite`](./signaturesuite.md#pure-mode-suites) / [`MlDsa{44,65,87}PreHashSuite`](./signaturesuite.md#prehash-mode-suites)                                           | `mldsa` + `sha3` (FIPS 204)                          | Lattice-based PQ signatures (pure + HashML-DSA)                      |
| [`SlhDsa{128f,192f,256f}Suite`](./signaturesuite.md#slh-dsa-pure-mode-suites) / [`SlhDsa{128f,192f,256f}PreHashSuite`](./signaturesuite.md#slh-dsa-prehash-mode-suites)             | `slhdsa` (+ `sha3` for prehash) (FIPS 205)           | Hash-based PQ signatures (pure + HashSLH-DSA)                        |
| [`Ed25519Suite`](./signaturesuite.md#ed25519-suites) / [`Ed25519PreHashSuite`](./signaturesuite.md#ed25519-suites)                                                                  | `curve25519` (+ `sha2` for prehash) (RFC 8032)       | Classical Ed25519 / Ed25519ph signatures                             |
| [`EcdsaP256Suite`](./signaturesuite.md#ecdsa-p256-suite)                                                                                                                            | `p256` + `sha2` (FIPS 186-5 §6)                      | Classical ECDSA-P256, hedged-by-default, low-S enforced              |
| [`MlDsa{44,65,87}SlhDsa{128f,192f,256f}Suite`](./signaturesuite.md#pq-only-hybrid-suites)                                                                                           | `mldsa` + `slhdsa` + `sha3`                          | PQ-only hybrid composite (ML-DSA + SLH-DSA)                          |
| [`MlDsa{44,65}Ed25519Suite`](./signaturesuite.md#classicalpq-hybrid-composite-encoding) / [`MlDsa{44,65}EcdsaP256Suite`](./signaturesuite.md#classicalpq-hybrid-composite-encoding) | `mldsa` + `sha3` + (`curve25519` \| `p256`) + `sha2` | Classical+PQ hybrid composite (`draft-ietf-lamps-pq-composite-sigs`) |


**High-Level Constructs.** Pure TypeScript abstractions over cipher suites.

| API                                                                                                                                                                                                                                             | Dependencies                     | Purpose                                            |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------- | -------------------------------------------------- |
| [`Seal`](./aead.md#seal) / [`SealStream`](./aead.md#sealstream) / [`OpenStream`](./aead.md#openstream) / [`SealStreamPool`](./aead.md#sealstreampool)                                                                                           | Any CipherSuite                  | One-shot, streaming, decrypting, and parallel AEAD |
| [`Sign`](./signing.md#sign) / [`SignStream`](./signing.md#signstream) / [`VerifyStream`](./signing.md#verifystream)                                                                                                                             | Any SignatureSuite               | One-shot and streaming digital signatures          |
| [`ratchetInit`](./ratchet.md#ratchetinitsk-context), [`KDFChain`](./ratchet.md#kdfchain), [`kemRatchetEncap`](./ratchet.md#kemratchetencapkem-rk-peerek-context)/[`kemRatchetDecap`](./ratchet.md#kemratchetdecapkem-rk-dk-kemct-ownek-context) | `sha2`; `mlkem` + `sha3` for KEM | Forward-secret session ratcheting (SPQR)           |
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

### AssemblyScript layer

`src/asm/` holds the AssemblyScript sources for each WASM binary. Every subdirectory compiles to its own `.wasm` with fully independent linear memory and no cross-module imports.

**Per-module conventions.** Every module exposes an `index.ts` as the asc entry point; it re-exports the public surface that becomes the WASM exports. Every module except `cte/` has a `buffers.ts` that defines the static memory layout and the offset getters that all other files in that module import. The `cte/` module is intentionally minimal: an `index.ts` whose layout is implicit in its single 64 KB page, and a sibling `shared.ts` exposing the `@inline` source-level `ctEqual` helper that other modules import.

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
├── blake3/
│   ├── index.ts
│   ├── buffers.ts         ← static linear-memory layout, MUTABLE_START / BUFFER_END
│   ├── flags.ts           ← BLAKE3 §2.2 Table 3 domain-separation flag constants
│   ├── compress.ts        ← v128-internal compress, BLAKE3 IV, SIGMA table
│   ├── compress_simd.ts   ← v128-external lane-parallel compress4
│   ├── chunk.ts           ← §2.4 chunk state machine (one-block lookahead)
│   └── tree.ts            ← §2.5 tree assembly + root finalize / XOF snapshot
├── chacha20/
│   ├── index.ts
│   ├── chacha20.ts          ← block function (RFC 8439)
│   ├── chacha20_simd_4x.ts  ← SIMD 4-wide inter-block keystream
│   ├── poly1305.ts          ← one-time MAC
│   ├── wipe.ts              ← module-wide buffer zeroizer
│   └── buffers.ts
├── cte/
│   ├── index.ts   ← v128 XOR-accumulate constant-time compare (cte.wasm)
│   └── shared.ts  ← @inline scalar ctEqual, imported by other AS modules
├── mlkem/
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

`src/ts/` is the public API layer. Each subdirectory is a published NPM subpath; top-level files cover cross-cutting concerns and standalone utilities.

**Subpath conventions.** Every cipher and hash module has an `index.ts` barrel, a `types.ts` for TypeScript-only declarations, and an `embedded.ts` that re-exports its gzip+base64 WASM blob from `src/ts/embedded/`. The `keccak/` alias subpath omits `types.ts` and re-exports sha3's instead. The `ratchet/` and `stream/` modules have no `embedded.ts` because they compose other modules and ship no WASM of their own.

**Cipher modules** (`serpent/`, `chacha20/`, `aes/`) add a `cipher-suite.ts` (the `CipherSuite` implementation for the seal layer), a `pool-worker.ts` (Web Worker source for `SealStreamPool`), a `generator.ts` (Fortuna `Generator`), and a `shared-ops.ts` (serpent) or `ops.ts` (chacha20, aes) holding pure primitive functions shared between the cipher-suite and the pool worker.

**Hash modules** (`sha2/`, `sha3/`) add a `hash.ts` (the stateless Fortuna `HashFn`).

**Signature module** (`mldsa/`) has no `cipher-suite.ts` or `pool-worker.ts` (signing and verification are not AEAD operations). It splits its surface into `keygen.ts`, `sign.ts`, `verify.ts`, `format.ts` (M' construction with domain separator and OID prefix), `hashvariant.ts` (the twelve §5.4.1 pre-hash dispatch), `expand.ts` (ExpandA, ExpandS, ExpandMask, SampleInBall via SHAKE), `validate.ts` (input validation), and `sha3-helpers.ts` (sponge orchestration).

**Signing surface** (`sign/`) sits beside `stream/` as the signing counterpart to the AEAD layer. `Sign`, `SignStream`, and `VerifyStream` are scheme-agnostic; they delegate to a `SignatureSuite` object passed at the call site (or to the stream constructor). The `sign/suites/` directory holds the in-tree suite consts. Shipped suites: six ML-DSA (three pure, three prehash), six SLH-DSA (three pure, three prehash), three PQ-only hybrid composites (`MlDsa44SlhDsa128fSuite`, `MlDsa65SlhDsa192fSuite`, `MlDsa87SlhDsa256fSuite`) that bind both primitives to the same prehash digest, two Ed25519 (pure plus Ed25519ph prehash), and one ECDSA-P256 (`EcdsaP256Suite` at format byte `0x02`, hedged-by-default, low-S enforced). Future work adds the classical+PQ hybrid composites. See [signing.md](./signing.md) for the `Sign` / `SignStream` / `VerifyStream` API and [signaturesuite.md](./signaturesuite.md) for the full suite catalog.

**Shared utilities.** `shared/` holds primitives reused across cipher modules without belonging to any one of them. `pkcs7.ts` is the canonical PKCS#7 padding helper used by Serpent CBC and consumer code.

**Build artifacts.** `cte-wasm.ts` and the `embedded/` directory hold auto-generated outputs that only exist after `bun bake`. Both are gitignored. `cte-wasm.ts` is the inline raw byte array of the cte WASM module. `embedded/` holds gzip+base64 blobs of each WASM binary (from `scripts/embed-wasm.ts`) and IIFE source strings for each pool worker (from `scripts/embed-workers.ts`).

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
├── blake3/
│   ├── embedded.ts
│   ├── index.ts          ← BLAKE3, BLAKE3Stream, keyed_hash / derive_key flavours, OutputReader, BLAKE3Hash
│   ├── types.ts          ← Blake3Exports (public), Blake3TestExports (test + blake3-tree substrate only)
│   └── validate.ts       ← key length, context non-empty, outLen finite-integer caller-side checks
├── chacha20/
│   ├── cipher-suite.ts
│   ├── embedded.ts
│   ├── generator.ts
│   ├── index.ts
│   ├── ops.ts
│   ├── pool-worker.ts
│   └── types.ts
├── cte-wasm.ts     ← gitignored build artifact: raw cte WASM bytes
├── embedded/       ← gitignored build artifacts
│   ├── aes-pool-worker.ts          ← AES pool-worker IIFE source string
│   ├── aes.ts                      ← aes.wasm gzip+base64 blob
│   ├── blake3.ts                   ← blake3.wasm gzip+base64 blob
│   ├── chacha20-pool-worker.ts     ← ChaCha20 pool-worker IIFE source string
│   ├── chacha20.ts                 ← chacha20.wasm gzip+base64 blob
│   ├── mlkem.ts                    ← mlkem.wasm gzip+base64 blob
│   ├── mldsa.ts                    ← mldsa.wasm gzip+base64 blob
│   ├── serpent-pool-worker.ts      ← Serpent pool-worker IIFE source string
│   ├── serpent.ts                  ← serpent.wasm gzip+base64 blob
│   ├── sha2.ts                     ← sha2.wasm gzip+base64 blob
│   └── sha3.ts                     ← sha3.wasm gzip+base64 blob
├── errors.ts       ← AuthenticationError, SigningError, KeyAgreementError, MerkleCodecError, MerkleLogError
├── fortuna.ts      ← Fortuna CSPRNG (composes pluggable Generator + HashFn)
├── index.ts        ← root barrel + dispatching init()
├── init.ts         ← initModule(), module cache, isInitialized
├── keccak/         ← alias subpath; same WASM and instance slot as sha3
│   ├── embedded.ts
│   └── index.ts
├── mlkem/
│   ├── embedded.ts
│   ├── indcpa.ts    ← IND-CPA encrypt/decrypt + matrix generation
│   ├── index.ts
│   ├── kem.ts       ← Fujisaki-Okamoto transform (keygen, encaps, decaps)
│   ├── params.ts    ← MLKEM512, MLKEM768, MLKEM1024 parameter sets
│   ├── suite.ts     ← MlKemSuite (hybrid KEM+AEAD CipherSuite factory)
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
├── merkle/
│   ├── blake3-tree.ts       ← Blake3Hasher + Blake3Tree (BLAKE3-native parent compress)
│   ├── checkpoint.ts        ← serializeCheckpointBody / parseCheckpointBody (c2sp.org/tlog-checkpoint §Note text)
│   ├── index.ts             ← public barrel
│   ├── merkle-log.ts        ← MerkleLog (normie producer surface, memory-backed)
│   ├── merkle-verifier.ts   ← MerkleVerifier (normie verify-only surface)
│   ├── proof.ts             ← verifyInclusionProof, verifyConsistencyProof, builders (RFC 9162 §2.1.3 / §2.1.4)
│   ├── sha256-tree.ts       ← Sha256Hasher + Sha256Tree (RFC 9162 §2.1.1 prefix bytes)
│   ├── signed-log.ts        ← SignedLog<S extends SignatureSuite> (danger-zone composition)
│   ├── signed-note.ts       ← envelope codec, key-ID derivation, cosignature codec, ALGO_REGISTRY
│   ├── storage.ts           ← MerkleStorage interface + MemoryStorage backend
│   ├── sth.ts               ← SignedTreeHead type
│   └── tree.ts              ← Hasher / MerkleTree interfaces + splitPoint / bit math
├── shared/
│   └── pkcs7.ts     ← canonical PKCS#7 padding helper (used by Serpent CBC + consumer code)
├── sign/
│   ├── ctx.ts              ← buildEffectiveCtx, prehashAlgoToMldsa, CTX_DOMAIN_MAX, USER_CTX_MAX
│   ├── envelope.ts         ← Sign (static single-shot signing + attached envelope)
│   ├── hasher.ts           ← running-prehash helper for SignStream / VerifyStream
│   ├── index.ts
│   ├── sign-stream.ts      ← SignStream (streaming signing for StreamableSignatureSuite)
│   ├── suites/
│   │   └── mldsa.ts        ← MlDsa{44,65,87}{,PreHash}Suite consts
│   ├── types.ts            ← SignatureSuite, StreamableSignatureSuite, PrehashAlgorithm
│   └── verify-stream.ts    ← VerifyStream (buffered streaming verification)
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
├── utils.ts        ← encoding, wipe, randomBytes, constantTimeEqual, CTE_MAX_BYTES, hasSIMD
└── wasm-source.ts  ← WasmSource union type
```

### Tests

`test/` holds three independent categories of files, used by separate workflows.

**Unit tests** (`unit/`) are Vitest suites that compile to a JS target for fast local iteration. The directory mirrors `src/ts/` structure with one folder per module, plus a handful of top-level `.test.ts` files for cross-cutting concerns (init, errors, utils, fortuna). CI splits these by domain via `unit-*.yml` for parallel execution.

**End-to-end tests** (`e2e/`) are Playwright suites that exercise the actual WASM artifacts across V8, SpiderMonkey, and JavaScriptCore. They run after the full build, including pool-worker bundling.

**Test vectors** (`vectors/`) is the immutable known-answer-test corpus. Files are read-only reference data. Some come from authoritative specifications (FIPS, RFCs, ACVP, NIST CAVP); others are self generated as regression vectors by `scripts/gen-*-vectors.ts`. CI validates KAT file integrity against `SHA256SUMS` and re-derives every Tier 2 byte against the [Rust verifier](./vector_audit.md) crate at `scripts/verify-vectors/` on every PR.

See [test-suite.md](./test-suite.md) for full testing methodology, vector corpus inventory with provenance, and gate discipline. See [vector_audit.md](./vector_audit.md) for the tier classification and verifier coverage.

```
test/
├── e2e/      ← Playwright suites against built WASM in V8, SpiderMonkey, JSC
├── unit/
│   ├── aes/
│   ├── chacha20/
│   ├── cte/
│   ├── errors.test.ts
│   ├── fortuna/
│   ├── fortuna.test.ts
│   ├── helpers.ts
│   ├── init/
│   ├── init.test.ts
│   ├── mlkem/
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

**Documentation.** `README.md` is the entry point. `SECURITY.md` covers the vulnerability disclosure policy. `AGENTS.md` is the agent contract that governs how AI agents work in the repo. `CHANGELOG.md` tracks release history and `LICENSE` is MIT. The `docs/` directory holds the full API reference, audits, benchmarks, and architecture notes (this file lives there).

**Package metadata.** `package.json` declares the NPM manifest, subpath exports, and scripts. `package-lock.json` and `bun.lock` are the lockfiles for NPM and bun respectively; both ship checked in so either tool can install reproducibly.

**Tool configs.** `asconfig.json` configures AssemblyScript compilation. `eslint.config.ts` is the active linter, run via `bun fix`. `playwright.config.ts` and `vitest.config.ts` configure the e2e and unit test runners. `tsconfig.json` is the base TypeScript config; `tsconfig.test.json` and `tsconfig.e2e.json` extend it for the test targets. `tslint.json` is a TSLint config (older format).

**Build artifacts** (gitignored; only exist after `bun bake`). `build/` holds the raw `.wasm` outputs from AssemblyScript compilation. `dist/` is the published NPM package contents (compiled JS, declarations, copied WASM, embedded blobs).

```
.
├── build/                ← gitignored: .wasm outputs from AS compilation
├── dist/                 ← gitignored: published NPM package contents
├── docs/                 ← API reference, audits, benchmarks (this file lives here)
├── README.md
├── SECURITY.md
├── AGENTS.md
├── CHANGELOG.md
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

## Build and CI

### Build Scripts

`scripts/` holds the build, codegen, and tooling scripts that produce `dist/` and the test-vector corpus, plus the independent Rust verifier crate. Four categories.

**Build orchestration.** Four top-level dispatchers front the package scripts: `build.ts` (the `bun bake` shorthand and the canonical `bun run build`), `test.ts` (`bun scripts/test.ts <unit|unit:group|e2e|e2e:install|all>`), `lint.ts` (`bun fix` and the canonical `bun run lint`), and `check.ts` (`bun check`, which runs a full build then lint + unit + e2e in parallel). They share a typed dependency DAG (`scripts/lib/build-graph.ts`), a parallel runner with per-task timing and colored output (`scripts/lib/parallel.ts`), the canonical twelve-module list (`scripts/lib/modules.ts`), and the per-CI-group test composition (`scripts/lib/test-groups.ts`). Underneath the dispatchers, the step scripts do the actual work: `build-asm.ts` drives AssemblyScript compilation across the twelve modules; `embed-wasm.ts` produces the gzip+base64 blob for each `.wasm`; `embed-workers.ts` bundles each pool worker into a self-contained IIFE via esbuild. See [Build Pipeline](#build-pipeline) for the full sequence.

**Codegen.** `generate_simd.ts` produces `src/asm/serpent/serpent_simd.ts` from a template by translating S-box gate logic into v128 ops; the generator and its output are both committed and the output is never edited by hand. `gen-seal-vectors.ts`, `gen-sealstream-vectors.ts`, `gen-fortuna-vectors.ts`, and `gen-ratchet-vectors.ts` produce known-answer-test vectors for their respective primitives.

**Tooling.** `gen-changelog.ts` generates `CHANGELOG.md` entries. `lint-asm.ts` lints the AssemblyScript sources via `asc --pedantic`. `pin-actions.ts` pins every GitHub Action reference to a SHA, run via `bun pin` after workflow changes.

**Independent verifier.** `verify-vectors/` is a standalone Rust crate that re-runs every Tier 2 KAT against RustCrypto primitives. It builds with a pinned toolchain and pinned dependencies, runs in CI under `verify-vectors.yml`, and shares no code with the leviathan-crypto WASM stack. Provenance details and tier classification live in [vector_audit.md](./vector_audit.md).

```
scripts/
├── build.ts             ← dispatcher · bun bake [target]
├── check.ts             ← dispatcher · bun check (build + lint + unit + e2e)
├── lint.ts              ← dispatcher · bun fix · bun scripts/lint.ts [ts|asm|all]
├── test.ts              ← dispatcher · bun scripts/test.ts [unit|unit:group <name>|e2e|e2e:install|all]
├── build-asm.ts
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

### Build Pipeline

<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/build-pipeline.svg" alt="Build Pipeline data flow diagram">

The build is orchestrated by `scripts/build.ts`, invoked via `bun bake` (or the canonical alias `bun run build`). The dispatcher walks a typed dependency DAG defined in `scripts/lib/build-graph.ts`, so each target builds only its prerequisites. Run a single target with `bun bake <target>` (e.g. `bun bake asm`, `bun bake ts`); the default target is `all`.

For the developer-facing workflow around these scripts (the iteration loop, single-file test invocation, when to use each shorthand), see [development.md](./development.md). This section documents what the pipeline does; the development doc covers how to use it day to day.

**Build targets and order.**

1. `asm`: AssemblyScript compiler reads each `src/asm/*/index.ts` for the twelve modules, emits `build/*.wasm`.
2. `embed`: `scripts/embed-wasm.ts` reads each `.wasm`, gzip compresses, base64 encodes, and writes to `src/ts/embedded/*.ts` and per-module `src/ts/*/embedded.ts`.
3. `embed-workers`: `scripts/embed-workers.ts` bundles each pool worker into a self-contained IIFE via esbuild and writes the source to `src/ts/embedded/<cipher>-pool-worker.ts` as a string export.
4. `ts`: TypeScript compiler emits `dist/`.
5. `wasm-copy`: `build/*.wasm` is copied into `dist/` for URL-based consumers.
6. `claude-md`: `docs/CLAUDE_consumer.md` is copied to the repository root as `CLAUDE.md` at `npm pack` time for in-package agent guidance.

**Runtime path (after build).**

7. Subpath consumer: `serpentInit(serpentWasm)` → `initModule()` → `loadWasm(source)` → decode gzip+base64 → `WebAssembly.instantiate` → cache in `init.ts`.
8. Root consumer: `init({ serpent: serpentWasm, sha2: sha2Wasm })` → dispatches to each module's init function via `Promise.all` → same path as step 7 per module.

`src/ts/embedded/` is gitignored; these files are build artifacts. The WASM blobs (`<module>.ts`) derive from the AssemblyScript source in `src/asm/`. The pool-worker bundles (`<cipher>-pool-worker.ts`) derive from the worker source in `src/ts/<cipher>/pool-worker.ts`, bundled as a self-contained IIFE by `scripts/embed-workers.ts`.

### CI/CD

`.github/` holds GitHub-specific repository configuration: workflow definitions, the CI image build context, and platform metadata. Workflows split along functional lines.

**Merge gate.** `build.yml`, `lint.yml`, `e2e.yml`, `test-suite.yml`. `test-suite.yml` orchestrates the per-domain unit runners (`unit-*.yml`) plus `verify-vectors.yml` for parallel execution and per-domain failure isolation.

**Test vectors.** `verify-vectors.yml` runs two sequenced jobs. `hashsums` reads `test/vectors/SHA256SUMS` and runs `sha256sum --check` against every pinned vector file, catching accidental edits or supply-chain tampering of the corpus. `rust-verify` depends on `hashsums`, builds the [Rust verifier](./vector_audit.md) crate at `scripts/verify-vectors/` with the pinned Rust toolchain (1.95.0) and pinned `Cargo.lock`, and re-derives every Tier 2 KAT byte from RustCrypto primitives that share zero code with leviathan-crypto's WASM stack. The verifier covers ten cipher targets: `xchacha`, `serpent`, `aes-gcm-siv`, `polyval`, `aes`, `aes-cbc`, `aes-ctr`, `aes-gcm`, `mlkem`, and `mldsa`. Cold builds take roughly 60 seconds; cached runs complete in under 15. See [vector_audit.md](./vector_audit.md) for the full tier classification, what the verifier proves, and what it does not.

**Release flow.** Manual `release.yml` bumps the version and creates the tag; the resulting `v*` tag push triggers `publish.yml`, which runs the NPM publish with provenance attestations. `npm-remove.yml` is the manual deprecate/unpublish escape hatch.

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
    ├── unit-mlkem.yml
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


See [Test Suite](#test-suite) for the testing methodology, vector corpus, and gate discipline that the CI workflows orchestrate.

---

## WebAssembly Modules

### WebAssembly is the deployment vehicle

<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/layers.svg" alt="Typescript Over Wasm layered diagram" width="700">

The JavaScript runtime compiles WASM bytecode to native machine code through its WASM JIT. V8 uses Liftoff and TurboFan; SpiderMonkey uses Baseline and Cranelift; JavaScriptCore uses BBQ and OMG. *There is no ahead-of-time path in mainstream engines today.*

**What makes the compiled output more predictable than equivalent JavaScript is not the absence of a JIT but the structure of the input.** Typed bytecode has no hidden-class transitions and no SMI/HeapNumber switching. Structured control flow has no computed gotos and no `eval`. There is no polymorphism-driven specialization, no deoptimization, no GC pauses, no string interning, and no shape changes mid-execution. The JS-level timing oracles that motivate constant-time-coding discipline (type guards, deopts, hidden classes, and intern pools) do not exist for WASM. WASM exposes the cipher to the same constant-time-coding discipline that native crypto follows.

**WASM linear memory is a buffer the library owns and wipes at operation boundaries.** JavaScript heap allocations leak copies into intern pools, nursery fragments, and old-space; WASM does not. Each cryptographic module compiles to its own isolated binary with its own linear memory. Code in the SHA-3 module cannot address key material in the Serpent module, even in principle. The only host-side bridge is the TypeScript orchestration layer, which sees inputs and outputs but never raw secret state.

See [wasm.md](./wasm.md) for a fuller primer on WebAssembly in the context of this library.

---

### Twelve Independent WASM Modules

Each primitive family compiles to its own `.wasm` binary with fully independent linear memory and buffer layouts. No shared state, no cross-module interference. Eleven of the twelve modules load through `init()`. The twelfth, `cte`, sits outside the public `Module` union and the `init()` gate; it occupies a single 64 KB memory page and lazy-loads on the first call to `constantTimeEqual`. The cte module backs the public `constantTimeEqual` and `CTE_MAX_BYTES` exports from the root barrel; neither requires an `init()` call.

| Module                               | Binary                                   | Primitives                                                                                                                                                                                                                                                                                                                                                                                                                               |
| ------------------------------------ | ---------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`serpent`](./serpent.md)            | [`serpent.wasm`](./asm_serpent.md)       | Serpent-256 block cipher: ECB, CTR mode, CBC mode                                                                                                                                                                                                                                                                                                                                                                                        |
| [`chacha20`](./chacha20.md)          | [`chacha20.wasm`](./asm_chacha.md)       | ChaCha20, Poly1305, ChaCha20-Poly1305 AEAD, XChaCha20-Poly1305 AEAD                                                                                                                                                                                                                                                                                                                                                                      |
| [`aes`](./aes.md)                    | [`aes.wasm`](./asm_aes.md)               | AES-128/192/256 block cipher (FIPS 197), CBC, CTR, GCM, GCM-SIV (RFC 8452)                                                                                                                                                                                                                                                                                                                                                               |
| [`sha2`](./sha2.md)                  | [`sha2.wasm`](./asm_sha2.md)             | SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, HMAC-SHA256, HMAC-SHA384, HMAC-SHA512                                                                                                                                                                                                                                                                                                                                      |
| [`sha3`](./sha3.md)                  | [`sha3.wasm`](./asm_sha3.md)             | SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256                                                                                                                                                                                                                                                                                                                                                                               |
| [`mlkem`](./mlkem.md)                | [`mlkem.wasm`](./asm_mlkem.md)           | ML-KEM polynomial arithmetic: SIMD NTT/invNTT (v128 butterflies with scalar tail), basemul, Montgomery/Barrett, CBD, compress, CT verify/cmov                                                                                                                                                                                                                                                                                            |
| [`mldsa`](./mldsa.md)                | [`mldsa.wasm`](./asm_mldsa.md)           | ML-DSA polynomial arithmetic: SIMD NTT/invNTT for q=8380417 (v128 i32 butterflies), Montgomery/Barrett over q, rejection sampling (RejNTTPoly, RejBoundedPoly), Power2Round, Decompose, HighBits, LowBits, MakeHint, UseHint, HintBitPack/Unpack with the §D.3 SUF-CMA checks, SampleInBall                                                                                                                                              |
| [`slhdsa`](./slhdsa.md)              | [`slhdsa.wasm`](./asm_slhdsa.md)         | SLH-DSA hash-based signing (FIPS 205): embedded Keccak permutation, F / H / T_ℓ / PRF / PRF_msg / H_msg tweakable hash family, 32-byte ADRS encoding, WOTS+ / FORS / XMSS / hypertree composition, slh_keygen_internal / slh_sign_internal / slh_verify_internal (§9 Algorithms 18 / 19 / 20)                                                                                                                                            |
| [`blake3`](./blake3.md)              | [`blake3.wasm`](./asm_blake3.md)         | BLAKE3 tree-mode hash family (BLAKE3 spec): v128-internal `compress` and lane-parallel `compress4` (§5.3 SIMD), §2.4 chunk machine, §2.5 tree assembly + root finalize (54-deep per §5.1.2), §2.6 XOF squeeze, §2.3 keyed_hash and derive_key. Tree-mode primitives (`_testChunkCV`, `_testParentCV`, `_testDeriveContextCV`) gated for test + blake3-tree substrate use; not part of the consumer-facing exports.                       |
| [`curve25519`](./ed25519.md)         | [`curve25519.wasm`](./asm_curve25519.md) | Ed25519 sign/verify (RFC 8032) and [X25519](./x25519.md) keygen/DH (RFC 7748) over GF(2^255-19). Scalar (no v128); see header comment in `src/asm/curve25519/index.ts` for the WASM-extmul analysis that motivates the scalar choice.                                                                                                                                                                                                    |
| [`p256`](./ecdsa-p256.md)            | [`p256.wasm`](./asm_p256.md)             | ECDSA sign/verify (FIPS 186-5 §6) over NIST P-256 (SP 800-186 §3.2.1.3). Field arithmetic with HMV §2.27 Solinas reduction, Renes-Costello-Batina 2016 complete addition / doubling (Algorithm 4 / 6 specialised for a = -3), RFC 6979 §3.2 deterministic + `draft-irtf-cfrg-det-sigs-with-noise-05` hedged nonce derivation, RFC 6979 §3.5 low-S enforcement on signer and verifier. Embedded SHA-256 + HMAC-SHA-256. Scalar (no v128). |
| [`cte`](./utils.md#constanttimeequal) | [`cte.wasm`](./asm_cte.md)              | SIMD constant-time byte equality. Backs `constantTimeEqual` and `CTE_MAX_BYTES`, lazy-loaded outside `init()`. Single 64 KB page. Sibling `src/asm/cte/shared.ts` exports the `@inline` scalar `ctEqual` that other AS modules import for in-WASM equality checks.                                                                                                                                                                       |

**Size.** Consumers who only use Serpent don't load the SHA-3 binary.

**Isolation.** Key material in `serpent.wasm` memory cannot bleed into `sha3.wasm` memory even in theory.

Each module's buffer layout starts at offset 0 and is defined in its own `buffers.ts`. Buffer layouts are fully independent across modules.

---

### Buffer Layouts

All offsets start at 0 per module. Independent linear memory. No offsets are shared or coordinated across modules. Per-module buffer tables (offset, size, name, purpose, and `wipeBuffers()` coverage) live in each module's WASM reference doc.

| Module       | Memory           | Layout reference                                                     |
| ------------ | ---------------- | -------------------------------------------------------------------- |
| `serpent`    | 3 pages (192 KB) | [asm_serpent.md#buffer-layout](./asm_serpent.md#buffer-layout)       |
| `chacha20`   | 3 pages (192 KB) | [asm_chacha.md#buffer-layout](./asm_chacha.md#buffer-layout)         |
| `aes`        | 4 pages (256 KB) | [asm_aes.md#buffer-layout](./asm_aes.md#buffer-layout)               |
| `sha2`       | 3 pages (192 KB) | [asm_sha2.md#buffer-layout](./asm_sha2.md#buffer-layout)             |
| `sha3`       | 3 pages (192 KB) | [asm_sha3.md#buffer-layout](./asm_sha3.md#buffer-layout)             |
| `mlkem`      | 3 pages (192 KB) | [asm_mlkem.md#buffer-layout](./asm_mlkem.md#buffer-layout)           |
| `mldsa`      | 4 pages (256 KB) | [asm_mldsa.md#buffer-layout](./asm_mldsa.md#buffer-layout)           |
| `slhdsa`     | 2 pages (128 KB) | [asm_slhdsa.md#buffer-layout](./asm_slhdsa.md#buffer-layout)         |
| `blake3`     | 2 pages (128 KB) | [asm_blake3.md#buffer-layout](./asm_blake3.md#buffer-layout)         |
| `curve25519` | 4 pages (256 KB) | [asm_curve25519.md#buffer-layout](./asm_curve25519.md#buffer-layout) |
| `p256`       | 3 pages (192 KB) | [asm_p256.md#buffer-layout](./asm_p256.md#buffer-layout)             |
| `cte`        | 1 page (64 KB)   | [asm_cte.md#memory-layout](./asm_cte.md#memory-layout) ‡             |

‡ [`cte`](./utils.md#constanttimeequal) is caller-determined with no static buffers or `wipeBuffers()` export

---


## `init()` API

WASM instantiation is async. [`init()`](./init.md) is the initialization gate, call it once before using any cryptographic class. The cost is explicit and the developer controls when it is paid.

### Signature

```typescript
type Module = 'serpent' | 'chacha20' | 'aes' | 'sha2' | 'sha3' | 'keccak' | 'mlkem' | 'mldsa' | 'slhdsa' | 'blake3' | 'curve25519' | 'p256'

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

The loading strategy is inferred from the source type, so there is no need for a mode string. Each module also exports its own init function for tree-shakeable imports:

| Module     | Init function                              |
| ---------- | ------------------------------------------ |
| serpent    | [serpentInit](./serpent.md#module-init)    |
| chacha20   | [chacha20Init](./chacha20.md#module-init)  |
| aes        | [aesInit](./aes.md#module-init)            |
| sha2       | [sha2Init](./sha2.md#module-init)          |
| sha3       | [sha3Init](./sha3.md#module-init)          |
| keccak     | [keccakInit](./sha3.md#module-init)        |
| mlkem      | [mlkemInit](./mlkem.md#init)               |
| mldsa      | [mldsaInit](./mldsa.md#init)               |
| slhdsa     | [slhdsaInit](./slhdsa.md#init)             |
| blake3     | [blake3Init](./blake3.md#module-init)      |
| ed25519    | [ed25519Init](./ed25519.md#init)           |
| x25519     | [x25519Init](./x25519.md#init)             |
| p256       | [ecdsaP256Init](./ecdsa-p256.md#init)      |

> [!NOTE]
> For enhanced semantic clarity, aliases are provided for two cryptographic primitives: [keccak](./sha3.md#keccakinit-alias) for [sha3](./sha3.md#sha3initsource), and [ed25519](./ed25519.md#init)/[x25519](./x25519.md#init) for [curve25519](./asm_curve25519.md). These aliases allow consumers to use the most contextually appropriate name. ML-KEM/ML-KEM users can write `init({ keccak: keccakWasm })` to specify the underlying sponge primitive, while signing consumers can use `init({ ed25519: source })` or `init({ x25519: source })` to match their chosen suite. Internally, each alias group shares a single WASM binary and instance slot; the initialization layer deduplicates identical sources. All of these names are accepted by [init()](./init.md#init), [initModule()](./init.md#functions), [getInstance()](./init.md#getinstance-internal), and [isInitialized()](./init.md#isinitialized).

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

### Pool worker spawn pattern

`SealStreamPool` spawns one Web Worker per pool slot through the cipher
suite's `createPoolWorker()` method. `SerpentCipher`, `XChaCha20Cipher`,
and `AESGCMSIVCipher` all implement the same classic-worker-over-blob-URL
pattern. The IIFE source is bundled at lib build time by
`scripts/embed-workers.ts` and embedded into each `cipher-suite.ts`
module as the `WORKER_SOURCE` string constant.

```typescript
createPoolWorker(): Worker {
	const blob = new Blob([WORKER_SOURCE], { type: 'application/javascript' });
	const url  = URL.createObjectURL(blob);
	const w    = new Worker(url);
	setTimeout(() => URL.revokeObjectURL(url), 0);
	return w;
}
```

The spawn body is short and every choice it encodes is load-bearing.

**Blob URL, not `new URL(..., import.meta.url)`.** Vite's transform hook
detects the `new Worker(new URL('./pool-worker.ts', import.meta.url))`
form at parse time and eagerly emits a separate worker chunk into the
consumer's bundle output, regardless of whether the consumer ever spawns
a pool. Building the URL from a runtime blob bypasses the eager-emission
path. Consumers that never instantiate `SealStreamPool` get zero worker
chunks.

**Classic worker, not module worker.** Chromium rejects module workers
loaded from `file://` origins (test pages, Electron, packaged docs).
Classic workers spawn cleanly under V8, SpiderMonkey, and JavaScriptCore
across every loader the library supports.

**Macrotask revoke, not synchronous revoke.** The Worker spec fetches the
URL synchronously at construction; revoking before the spawn completes
drops the spawn on the floor. Revoking on the next macrotask releases
the ~5 KB blob immediately, instead of leaking it for the document's
lifetime.

> [!NOTE]
> Strict-CSP consumers (`worker-src 'self'`, no `blob:`) can supply
> their own URL-based factory by spread-overriding `createPoolWorker`
> on the cipher object. See [ciphersuite.md](./ciphersuite.md#interface-reference)
> for the override pattern. This is also required for WebKit/Safari: it
> refuses the `blob:` worker resource under a restrictive CSP even with
> `worker-src blob:` present, while Chromium and Firefox admit it. The
> override path works on all three engines. See [csp.md](./csp.md) for the
> full directive reference and per-engine behavior.

---

## Public API Classes

| Classes                                                                                                                                                                                                                                                                                                                                                                                                                        | Description / composition                                                                                                                                                                             | Required modules                                  |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| [`Serpent`](./serpent.md#serpent), [`SerpentCtr`](./serpent.md#serpentctr), [`SerpentCbc`](./serpent.md#serpentcbc), [`SerpentGenerator`](./serpent.md#serpentgenerator)                                                                                                                                                                                                                                                       | Serpent-256 block cipher (ECB, CTR, CBC); `SerpentGenerator` is a Fortuna PRF source                                                                                                                  | `serpent`                                         |
| [`SerpentCipher`](./ciphersuite.md#serpentcipher)                                                                                                                                                                                                                                                                                                                                                                              | Tier 2 CipherSuite: Serpent-CBC + HMAC-SHA256 + HKDF-SHA256                                                                                                                                           | `serpent` + `sha2`                                |
| [`ChaCha20`](./chacha20.md#chacha20), [`Poly1305`](./chacha20.md#poly1305), [`ChaCha20Poly1305`](./chacha20.md#chacha20poly1305), [`XChaCha20Poly1305`](./chacha20.md#xchacha20poly1305), [`ChaCha20Generator`](./chacha20.md#chacha20generator)                                                                                                                                                                               | ChaCha20 stream cipher, Poly1305 MAC, AEAD constructions; `ChaCha20Generator` is a Fortuna PRF source                                                                                                 | `chacha20`                                        |
| [`XChaCha20Cipher`](./ciphersuite.md#xchacha20cipher)                                                                                                                                                                                                                                                                                                                                                                          | Tier 2 CipherSuite: HKDF-SHA256 + HChaCha20 + XChaCha20-Poly1305 per chunk                                                                                                                            | `chacha20` + `sha2`                               |
| [`AES`](./aes.md#aes), [`AESCbc`](./aes.md#aescbc), [`AESCtr`](./aes.md#aesctr), [`AESGCM`](./aes.md#aesgcm), [`AESGCMSIV`](./aes.md#aesgcmsiv), [`AESGenerator`](./aes.md#aesgenerator)                                                                                                                                                                                                                                       | AES-128/192/256 block cipher (CBC, CTR, GCM, GCM-SIV); `AESGenerator` is a Fortuna PRF source                                                                                                         | `aes`                                             |
| [`AESGCMSIVCipher`](./ciphersuite.md#aesgcmsivcipher)                                                                                                                                                                                                                                                                                                                                                                          | Tier 2 CipherSuite: HKDF-SHA256 + AES-256-GCM-SIV per chunk + 32-byte explicit commitment                                                                                                             | `aes` + `sha2`                                    |
| [`SHA256`](./sha2.md#sha256), [`SHA384`](./sha2.md#sha384), [`SHA512`](./sha2.md#sha512), [`SHA224`](./sha2.md#sha224), [`SHA512_224`](./sha2.md#sha512_224), [`SHA512_256`](./sha2.md#sha512_256), [`HMAC_SHA256`](./sha2.md#hmac_sha256), [`HMAC_SHA384`](./sha2.md#hmac_sha384), [`HMAC_SHA512`](./sha2.md#hmac_sha512), [`HKDF_SHA256`](./sha2.md#hkdf_sha256), [`HKDF_SHA512`](./sha2.md#hkdf_sha512)                     | SHA-2 hashes, HMACs (RFC 2104), HKDF (RFC 5869 extract+expand, pure-TS over HMAC)                                                                                                                     | `sha2`                                            |
| [`SHA3_224`](./sha3.md#sha3_224), [`SHA3_256`](./sha3.md#sha3_256), [`SHA3_384`](./sha3.md#sha3_384), [`SHA3_512`](./sha3.md#sha3_512), [`SHAKE128`](./sha3.md#shake128), [`SHAKE256`](./sha3.md#shake256), [`CSHAKE128`](./kmac.md#cshake128), [`CSHAKE256`](./kmac.md#cshake256), [`KMAC128`](./kmac.md#kmac128), [`KMAC256`](./kmac.md#kmac256), [`KMACXOF128`](./kmac.md#kmacxof128), [`KMACXOF256`](./kmac.md#kmacxof256) | SHA-3 hashes, SHAKE XOFs, cSHAKE and KMAC (SP 800-185)                                                                                                                                                | `sha3`                                            |
| [`MlKem512`](./mlkem.md#mlkem-api), [`MlKem768`](./mlkem.md#mlkem-api), [`MlKem1024`](./mlkem.md#mlkem-api)                                                                                                                                                                                                                                                                                                                    | ML-KEM (FIPS 203) key encapsulation                                                                                                                                                                   | `mlkem` + `sha3`                                  |
| [`MlKemSuite`](./mlkem.md#mlkemsuite)                                                                                                                                                                                                                                                                                                                                                                                          | Hybrid KEM+AEAD CipherSuite factory: encaps/decaps + HKDF with kemCt binding + inner CipherSuite                                                                                                      | `mlkem` + `sha3` + inner cipher                   |
| [`MlDsa44`](./mldsa.md#mldsa-api), [`MlDsa65`](./mldsa.md#mldsa-api), [`MlDsa87`](./mldsa.md#mldsa-api); [`MlDsa{44,65,87}Suite`](./signaturesuite.md#pure-mode-suites); [`MlDsa{44,65,87}PreHashSuite`](./signaturesuite.md#prehash-mode-suites)                                                                                                                                                                              | ML-DSA (FIPS 204) signatures: pure + HashML-DSA with SHA-3/SHAKE prehash; pure-mode and prehash signature suites included                                                                             | `mldsa` + `sha3`                                  |
| `MlDsa{44,65,87}` [HashML-DSA](./mldsa.md#hashml-dsa-pre-hash-variant) with SHA-2 prehash                                                                                                                                                                                                                                                                                                                                      | HashML-DSA with SHA-2 family prehash (SHA2-{224,256,384,512,512/224,512/256}) per FIPS 204 §5.4.1                                                                                                     | `mldsa` + `sha3` + `sha2`                         |
| [`SlhDsa128f`](./slhdsa.md#slhdsa-api), [`SlhDsa192f`](./slhdsa.md#slhdsa-api), [`SlhDsa256f`](./slhdsa.md#slhdsa-api); [`SlhDsa{128f,192f,256f}Suite`](./signaturesuite.md#slh-dsa-pure-mode-suites)                                                                                                                                                                                                                          | SLH-DSA (FIPS 205) hash-based signatures; binary embeds its own Keccak so pure SLH-DSA doesn't require `sha3`                                                                                         | `slhdsa`                                          |
| `SlhDsa{128f,192f,256f}` [HashSLH-DSA](./slhdsa.md#hashslh-dsa-pre-hash-variant) over SHA-3/SHAKE prehash; [`SlhDsa{128f,192f,256f}PreHashSuite`](./signaturesuite.md#slh-dsa-prehash-mode-suites)                                                                                                                                                                                                                             | HashSLH-DSA with SHA-3/SHAKE prehash; streaming `SignStream` drives the prehash through `sha3`                                                                                                        | `slhdsa` + `sha3`                                 |
| `SlhDsa{128f,192f,256f}` [HashSLH-DSA](./slhdsa.md#hashslh-dsa-pre-hash-variant) over SHA-2 prehash                                                                                                                                                                                                                                                                                                                            | HashSLH-DSA with SHA-2 family prehash                                                                                                                                                                 | `slhdsa` + `sha3` + `sha2`                        |
| [`MlDsa44SlhDsa128fSuite`](./signaturesuite.md#pq-only-hybrid-suites), [`MlDsa65SlhDsa192fSuite`](./signaturesuite.md#pq-only-hybrid-suites), [`MlDsa87SlhDsa256fSuite`](./signaturesuite.md#pq-only-hybrid-suites)                                                                                                                                                                                                            | PQ-only hybrid composites (ML-DSA + SLH-DSA); both sub-verifies always run                                                                                                                            | `mldsa` + `sha3` + `slhdsa`                       |
| [`Ed25519`](./ed25519.md#ed25519-api), [`X25519`](./x25519.md#x25519-api); [`Ed25519Suite`](./signaturesuite.md#ed25519suite-pure)                                                                                                                                                                                                                                                                                             | Classical Ed25519 sign/verify (pure + Ed25519ph) and X25519 Diffie-Hellman. `Ed25519Suite` (fmt `0x01`) is pure mode. `X25519.dh` throws `KeyAgreementError` on all-zero shared secret (RFC 7748 §7). | `curve25519`                                      |
| [`Ed25519PreHashSuite`](./signaturesuite.md#ed25519prehashsuite-prehash-ed25519ph)                                                                                                                                                                                                                                                                                                                                             | Ed25519ph suite (fmt `0x11`): SHA-512 prehash with dom2(F=1, ctx) binding                                                                                                                             | `curve25519` + `sha2`                             |
| [`EcdsaP256`](./ecdsa-p256.md#ecdsa-p256-api), [`ecdsaSignatureToDer`](./ecdsa-p256.md#ecdsasignaturetoderrawsig), [`ecdsaSignatureFromDer`](./ecdsa-p256.md#ecdsasignaturefromderdersig), [`encodeEcPrivateKey`](./ecdsa-p256.md#encodeecprivatekeyscalar), [`decodeEcPrivateKey`](./ecdsa-p256.md#decodeecprivatekeyder), [`pointDecompress`](./ecdsa-p256.md#pointdecompresspk33)                                           | Classical ECDSA over NIST P-256; pure-TS DER codec helpers for X.509 / JWS / SEC 1 interop per RFC 3279 §2.2.3                                                                                        | `p256`                                            |
| [`EcdsaP256Suite`](./signaturesuite.md#ecdsa-p256-suite)                                                                                                                                                                                                                                                                                                                                                                       | ECDSA-P256 suite (fmt `0x02`): SHA-256 streaming prehash, hedged-by-default per `draft-irtf-cfrg-det-sigs-with-noise-05`                                                                              | `p256` + `sha2`                                   |
| [`MlDsa44Ed25519Suite`](./signaturesuite.md#classicalpq-hybrid-composite-encoding), [`MlDsa65Ed25519Suite`](./signaturesuite.md#classicalpq-hybrid-composite-encoding)                                                                                                                                                                                                                                                         | Classical+PQ hybrid (composite ML-DSA + Ed25519, fmt `0x20`/`0x21`) per `draft-ietf-lamps-pq-composite-sigs`                                                                                          | `mldsa` + `sha3` + `curve25519` + `sha2`          |
| [`MlDsa44EcdsaP256Suite`](./signaturesuite.md#classicalpq-hybrid-composite-encoding), [`MlDsa65EcdsaP256Suite`](./signaturesuite.md#classicalpq-hybrid-composite-encoding)                                                                                                                                                                                                                                                     | Classical+PQ hybrid (composite ML-DSA + ECDSA-P256, fmt `0x22`/`0x23`) per `draft-ietf-lamps-pq-composite-sigs`                                                                                       | `mldsa` + `sha3` + `p256` + `sha2`                |
| [`BLAKE3`](./blake3.md#blake3), [`BLAKE3Stream`](./blake3.md#blake3stream), [`BLAKE3KeyedHash`](./blake3.md#blake3keyedhash), [`BLAKE3KeyedHashStream`](./blake3.md#blake3keyedhashstream), [`BLAKE3DeriveKey`](./blake3.md#blake3derivekey), [`BLAKE3DeriveKeyStream`](./blake3.md#blake3derivekeystream), [`BLAKE3OutputReader`](./blake3.md#blake3outputreader), [`BLAKE3Hash`](./blake3.md#blake3hash)                     | BLAKE3 tree-mode hash family (hash, keyed_hash, derive_key, XOF reader); `BLAKE3Hash` is a stateless Fortuna `HashFn` const                                                                           | `blake3`                                          |
| [`Sign`](./signing.md#sign), [`SignStream`](./signing.md#signstream), [`VerifyStream`](./signing.md#verifystream)                                                                                                                                                                                                                                                                                                              | Scheme-agnostic signing layer ‡                                                                                                                                                                       | varies (per `SignatureSuite`)                     |
| [`Seal`](./aead.md#seal), [`SealStream`](./aead.md#sealstream), [`OpenStream`](./aead.md#openstream), [`SealStreamPool`](./aead.md#sealstreampool)                                                                                                                                                                                                                                                                             | Cipher-agnostic AEAD layer; `SealStreamPool` also takes a `WasmSource` in pool opts for worker compilation                                                                                            | varies (per `CipherSuite`)                        |
| [`MerkleVerifier`](./merkle.md#merkleverifier), [`MerkleLog`](./merkle.md#merklelog), [`SignedLog`](./merkle.md#signedlog), [`Sha256Tree`](./merkle.md#sha256tree-and-blake3tree), [`Blake3Tree`](./merkle.md#sha256tree-and-blake3tree), [`MemoryStorage`](./merkle.md#merklestorage-and-memorystorage)                                                                                                                       | Transparency log: `MerkleVerifier` / `MerkleLog` (normie surface); `SignedLog`, `Sha256Tree`, `Blake3Tree`, `MemoryStorage` (danger-zone composition)                                                 | `sha2` (+ suite + hasher modules for `SignedLog`) |
| [`ratchetInit`](./ratchet.md#ratchetinitsk-context), [`KDFChain`](./ratchet.md#kdfchain), [`SkippedKeyStore`](./ratchet.md#skippedkeystore)                                                                                                                                                                                                                                                                                    | SPQR KDF primitives ‡                                                                                                                                                                                 | `sha2`                                            |
| [`kemRatchetEncap`](./ratchet.md#kemratchetencapkem-rk-peerek-context), [`kemRatchetDecap`](./ratchet.md#kemratchetdecapkem-rk-dk-kemct-ownek-context), [`RatchetKeypair`](./ratchet.md#ratchetkeypair)                                                                                                                                                                                                                        | SPQR ML-KEM ratchet step (post-compromise security) †                                                                                                                                                 | `mlkem` + `sha3` + `sha2`                         |
| [`Fortuna`](./fortuna.md)                                                                                                                                                                                                                                                                                                                                                                                                      | CSPRNG with forward secrecy; pluggable generator (Serpent / ChaCha20 / AES) × hash (SHA-256 / SHA3-256 / BLAKE3)                                                                                      | cipher PRF + hash module                          |

> [!NOTE]
> Class names match conventional cryptographic notation. HMAC names use underscore separator (`HMAC_SHA256`) matching RFC convention; SHA-3 names use underscore separator (`SHA3_256`) for readability.
>
> † Ratchet exports are KDF primitives from Signal's Sparse Post-Quantum Ratchet spec; session state, message ordering, and header format remain application concerns.
>
> ‡ `Sign`, `SignStream`, and `VerifyStream` accept any `SignatureSuite` from the catalog: `MlDsa{44,65,87}{,PreHash}Suite`, `SlhDsa{128f,192f,256f}{,PreHash}Suite`, the PQ-only hybrid composites `MlDsa{44,65,87}SlhDsa{128f,192f,256f}Suite`, `Ed25519{,PreHash}Suite`, `EcdsaP256Suite`, and the classical+PQ hybrids `MlDsa{44,65}{Ed25519,EcdsaP256}Suite`. See [signing.md](./signing.md) for the user-facing API and [signaturesuite.md](./signaturesuite.md) for the suite catalog.

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
|Encoding|[`hexToBytes`](./utils.md#hextobytes), [`bytesToHex`](./utils.md#bytestohex), [`utf8ToBytes`](./utils.md#utf8tobytes), [`bytesToUtf8`](./utils.md#bytestoutf8), [`base64ToBytes`](./utils.md#base64tobytes), [`bytesToBase64`](./utils.md#bytestobase64)|
|Security|[`constantTimeEqual`](./utils.md#constanttimeequal), [`CTE_MAX_BYTES`](./utils.md#cte_max_bytes), [`wipe`](./utils.md#wipe), [`xor`](./utils.md#xor)|
|Helpers|[`concat`](./utils.md#concat), [`randomBytes`](./utils.md#randombytes), [`hasSIMD`](./utils.md#hassimd)|
|Types|[`Hash`](./types.md#hash), [`KeyedHash`](./types.md#keyedhash), [`Blockcipher`](./types.md#blockcipher), [`Streamcipher`](./types.md#streamcipher), [`AEAD`](./types.md#aead), [`Generator`](./types.md#generator), [`HashFn`](./types.md#hashfn), [`CipherSuite`](./types.md#ciphersuite), [`SignatureSuite`](./signaturesuite.md#signaturesuite), [`StreamableSignatureSuite`](./signaturesuite.md#streamablesignaturesuite-extends-signaturesuite), [`PrehashAlgorithm`](./signaturesuite.md#prehashalgorithm)|

---

## Module Relationships

### ASM layer: internal import graph

Each WASM module is fully independent at the binary level (no cross-module imports). Inside each module, files form a small dependency DAG: buffer-offset getters from `buffers.ts` flow into every consumer, and mode files (CBC, CTR, GCM, etc.) consume the core block-cipher or hash primitives.

The per-module import trees live in [asm_imports.md](./asm_imports.md). For per-file source-level descriptions, see the [AssemblyScript layer tree](#assemblyscript-layer) above.

### TS layer: internal import graph

<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/import-graph.svg" alt="TS Layer: internal import graph diagram">

Each module's [init function](#init-api) calls `initModule()` from `init.ts`, passing a `WasmSource`. `initModule()` delegates to [`loadWasm(source)`](./loader.md#loadwasmsource) in `loader.ts`. The loader infers the loading strategy from the source type, with no mode string and no knowledge of module names or embedded file paths.

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
| `SHA224`      | `sha224Init`, `sha256Update`, `sha224Final`, `wipeBuffers` + buffer getters                                                 |
| `SHA512`      | `sha512Init`, `sha512Update`, `sha512Final`, `wipeBuffers` + buffer getters                                                 |
| `SHA384`      | `sha384Init`, `sha512Update`, `sha384Final`, `wipeBuffers` + buffer getters                                                 |
| `SHA512_224`  | `sha512_224Init`, `sha512Update`, `sha512_224Final`, `wipeBuffers` + buffer getters                                         |
| `SHA512_256`  | `sha512_256Init`, `sha512Update`, `sha512_256Final`, `wipeBuffers` + buffer getters                                         |
| `HMAC_SHA256` | `hmac256Init`, `hmac256Update`, `hmac256Final`, `sha256Init`, `sha256Update`, `sha256Final`, `wipeBuffers` + buffer getters |
| `HMAC_SHA512` | `hmac512Init`, `hmac512Update`, `hmac512Final`, `sha512Init`, `sha512Update`, `sha512Final`, `wipeBuffers` + buffer getters |
| `HMAC_SHA384` | `hmac384Init`, `hmac384Update`, `hmac384Final`, `sha384Init`, `sha512Update`, `sha384Final`, `wipeBuffers` + buffer getters |
| `SHA256Hash`  | `sha256Init`, `sha256Update`, `sha256Final`, `wipeBuffers` + buffer getters                                                 |

**sha3/index.ts → asm/sha3/ (Tier 1: direct WASM callers)**

| TS Class         | WASM functions called                                                                            |
| ---------------- | ------------------------------------------------------------------------------------------------ |
| `SHA3_224`       | `sha3_224Init`, `keccakAbsorb`, `sha3_224Final`, `wipeBuffers` + buffer getters                  |
| `SHA3_256`       | `sha3_256Init`, `keccakAbsorb`, `sha3_256Final`, `wipeBuffers` + buffer getters                  |
| `SHA3_384`       | `sha3_384Init`, `keccakAbsorb`, `sha3_384Final`, `wipeBuffers` + buffer getters                  |
| `SHA3_512`       | `sha3_512Init`, `keccakAbsorb`, `sha3_512Final`, `wipeBuffers` + buffer getters                  |
| `SHA3_256Stream` | `sha3_256Init`, `keccakAbsorb`, `sha3_256Final`, `wipeBuffers` + buffer getters                  |
| `SHA3_512Stream` | `sha3_512Init`, `keccakAbsorb`, `sha3_512Final`, `wipeBuffers` + buffer getters                  |
| `SHAKE128`       | `shake128Init`, `keccakAbsorb`, `shakePad`, `shakeSqueezeBlock`, `wipeBuffers` + buffer getters  |
| `SHAKE256`       | `shake256Init`, `keccakAbsorb`, `shakePad`, `shakeSqueezeBlock`, `wipeBuffers` + buffer getters  |
| `SHAKE128Stream` | `shake128Init`, `keccakAbsorb`, `shakePad`, `shakeSqueezeBlock`, `wipeBuffers` + buffer getters  |
| `SHAKE256Stream` | `shake256Init`, `keccakAbsorb`, `shakePad`, `shakeSqueezeBlock`, `wipeBuffers` + buffer getters  |
| `SHA3_256Hash`   | `sha3_256Init`, `keccakAbsorb`, `sha3_256Final`, `wipeBuffers` + buffer getters                  |
| `CSHAKE128`      | `cshake128Init`, `keccakAbsorb`, `shakePad`, `shakeSqueezeBlock`, `wipeBuffers` + buffer getters |
| `CSHAKE256`      | `cshake256Init`, `keccakAbsorb`, `shakePad`, `shakeSqueezeBlock`, `wipeBuffers` + buffer getters |
| `KMAC128`        | `cshake128Init`, `keccakAbsorb`, `shakePad`, `shakeSqueezeBlock`, `wipeBuffers` + buffer getters |
| `KMAC256`        | `cshake256Init`, `keccakAbsorb`, `shakePad`, `shakeSqueezeBlock`, `wipeBuffers` + buffer getters |
| `KMACXOF128`     | `cshake128Init`, `keccakAbsorb`, `shakePad`, `shakeSqueezeBlock`, `wipeBuffers` + buffer getters |
| `KMACXOF256`     | `cshake256Init`, `keccakAbsorb`, `shakePad`, `shakeSqueezeBlock`, `wipeBuffers` + buffer getters |

**mlkem/index.ts + mlkem/kem.ts + mlkem/indcpa.ts → asm/mlkem/ (Tier 1)**

| TS Class                            | WASM functions called                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `MlKem512`, `MlKem768`, `MlKem1024` | `polyvec_ntt`, `polyvec_invntt`, `polyvec_basemul_acc_montgomery`, `polyvec_add`, `polyvec_reduce`, `polyvec_tobytes`, `polyvec_frombytes`, `polyvec_compress`, `polyvec_decompress`, `poly_ntt`, `poly_invntt`, `poly_tomont`, `poly_add`, `poly_sub`, `poly_reduce`, `poly_basemul_montgomery`, `poly_frommsg`, `poly_tomsg`, `poly_compress`, `poly_decompress`, `poly_getnoise`, `rej_uniform`, `ct_verify`, `ct_cmov`, `wipeBuffers` + buffer getters |

All MlKem classes also call sha3 WASM via `indcpa.ts`: `sha3_256Init`, `sha3_512Init`, `shake128Init`, `shake256Init`, `keccakAbsorb`, `sha3_256Final`, `sha3_512Final`, `shakeFinal`, `shakePad`, `shakeSqueezeBlock`.

**mldsa/index.ts + mldsa/{keygen,sign,verify}.ts → asm/mldsa/ (Tier 1)**

| TS Class                        | WASM functions called                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `MlDsa44`, `MlDsa65`, `MlDsa87` | `rej_ntt_poly`, `rej_bounded_poly`, `sample_in_ball`, `power2round_polyvec`, `decompose_polyvec`, `high_bits_polyvec`, `low_bits_polyvec`, `make_hint_polyvec`, `use_hint_polyvec`, `hint_bit_pack`, `hint_bit_unpack` (returns -1 on §D.3 malformed input), `polyvec_ntt`/`polyvec_invntt`, `polyvec_pointwise_montgomery`, `polyvec_add`/`polyvec_sub`/`polyvec_reduce`, `poly_ntt`/`poly_invntt`/`poly_pointwise_montgomery`, `pack_pk`/`unpack_pk`, `pack_sk`/`unpack_sk`, `pack_sig`/`unpack_sig`, `wipeBuffers` + buffer getters |

All MlDsa classes also call sha3 WASM via `expand.ts` and `sha3-helpers.ts`: SHAKE128 for `ExpandA` (matrix Â), SHAKE256 for `ExpandS`, `ExpandMask`, message representative μ, ρ'' derivation, and `SampleInBall`. HashML-DSA additionally calls sha2 (or sha3) functions for the §5.4.1 pre-hash before formatting M'.

**slhdsa/index.ts + slhdsa/{keygen,sign,verify}.ts → asm/slhdsa/ (Tier 1)**

| TS Class                                    | WASM functions called                                                                                                                                                                                                                                                                                            |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SlhDsa128f`, `SlhDsa192f`, `SlhDsa256f`    | `slhKeygenInternal` (FIPS 205 Algorithm 18), `slhSignInternal` (Algorithm 19), `slhVerifyInternal` (Algorithm 20), `setParams<128f\|192f\|256f>`, `wipeBuffers` + buffer getters. HashSLH-DSA additionally calls sha3 (SHAKE128 / SHAKE256 / SHA3-256 / SHA3-512) or sha2 functions for the §10.2 pre-hash before building M'. |

The `slhdsa.wasm` binary embeds its own Keccak permutation, so pure-mode SLH-DSA never calls into `sha3.wasm`. Prehash SLH-DSA touches `sha3.wasm` only for the TS-layer running digest in the `SignStream` / `VerifyStream` path. The `_test*` prefixed exports drive individual layers (WOTS+, FORS, XMSS, hypertree) in isolation during unit testing and are not part of `SlhDsaExports`.

**blake3/index.ts → asm/blake3/ (Tier 1)**

| TS Class                                                                                                                               | WASM functions called                                                                                                                                                                                                    |
| -------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `BLAKE3`, `BLAKE3Stream`, `BLAKE3KeyedHash`, `BLAKE3KeyedHashStream`, `BLAKE3DeriveKey`, `BLAKE3DeriveKeyStream`, `BLAKE3OutputReader` | `hashInit`, `keyedHashInit`, `deriveKeyInit`, `chunkUpdate`, `chunkFinalize`, `treeFinalizeRoot`, `squeezeXofBlock`, `wipeBuffers` + buffer getters. SIMD: `compress4` for chunk/parent batches (dispatched internally). |
| `BLAKE3Hash`                                                                                                                           | `hashInit`, `chunkUpdate`, `chunkFinalize`, `wipeBuffers` + buffer getters (stateless `HashFn` const, 32-byte output for Fortuna).                                                                                       |

The tree-mode test exports `_testChunkCV`, `_testParentCV`, and `_testDeriveContextCV` are not part of the consumer-facing `Blake3Exports` interface; they back `src/ts/merkle/blake3-tree.ts` and the tree-internals unit suite. `BLAKE3OutputReader` holds the `blake3` module exclusivity token until `dispose()` so sequential `read(n)` calls share the §2.6 root-state snapshot.

**curve25519/index.ts (re-exported via ed25519/, x25519/) → asm/curve25519/ (Tier 1)**

| TS Class    | WASM functions called                                                                                                                                                                                                       |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Ed25519`   | `ed25519Keygen`, `ed25519KeygenDerand`, `ed25519Sign`, `ed25519SignPrehashed`, `ed25519Verify`, `ed25519VerifyPrehashed`, `ed25519SignInternalPk`, `ed25519SignPrehashedInternalPk`, `wipeBuffers` + buffer getters         |
| `X25519`    | `x25519Keygen`, `x25519KeygenDerand`, `x25519Dh`, `wipeBuffers` + buffer getters                                                                                                                                            |

Both classes share `curve25519.wasm`; the init layer aliases `ed25519` and `x25519` to the same instance slot and de-dupes given identical sources. The module embeds its own SHA-512 (verbatim port from `src/asm/sha2/sha512.ts`) for the Ed25519 hash chain so pure-mode Ed25519 never crosses the WASM boundary mid-signature. The `*InternalPk` suite-layer exports skip the fault-injection cross-check; direct-class callers use the public `sign(sk, pk, M)` entry points with the cross-check intact.

**ecdsa/index.ts → asm/p256/ (Tier 1)**

| TS Class    | WASM functions called                                                                                                                    |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `EcdsaP256` | `ecdsaKeygen`, `ecdsaKeygenDerand`, `ecdsaSign`, `ecdsaSignInternalPk`, `ecdsaVerify`, `pointDecompress`, `wipeBuffers` + buffer getters |

The `p256.wasm` binary embeds its own SHA-256 + HMAC-SHA-256 (verbatim ports from `src/asm/sha2/`) for the RFC 6979 §3.2 HMAC-DRBG K-derivation chain; signing keeps every chain iteration inside a single WASM call. `EcdsaP256Suite` calls into the same module via `signPrehashed` / `verifyPrehashed`-shaped routing through `_signInternalPk`, plus sha2 (`SHA256`) at the TS layer for the streaming prehash path. DER codec helpers (`ecdsaSignatureToDer`, `ecdsaSignatureFromDer`, `encodeEcPrivateKey`, `decodeEcPrivateKey`) are pure TypeScript (RFC 3279 §2.2.3, RFC 5915) and call no WASM.

**Tier 2: pure TS composition**

| TS Class / Object                                                   | Composes                                                                                                                                               |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `SerpentCipher`                                                     | `SerpentCbc` + `HMAC_SHA256` + `HKDF_SHA256`                                                                                                           |
| `XChaCha20Cipher`                                                   | `ChaCha20Poly1305` (via `ops.ts`) + `HKDF_SHA256`                                                                                                      |
| `AESGCMSIVCipher`                                                   | `AESGCMSIV` (via `ops.ts`) + `HKDF_SHA256`                                                                                                             |
| `Seal`                                                              | `SealStream` + `OpenStream` (degenerate single-chunk case)                                                                                             |
| `SealStream`                                                        | `CipherSuite` (generic, caller provides cipher)                                                                                                        |
| `OpenStream`                                                        | `CipherSuite` (generic, caller provides cipher)                                                                                                        |
| `SealStreamPool`                                                    | `CipherSuite` + `compileWasm()` + Web Workers                                                                                                          |
| `HKDF_SHA256`                                                       | `HMAC_SHA256` (extract + expand per RFC 5869)                                                                                                          |
| `HKDF_SHA512`                                                       | `HMAC_SHA512` (extract + expand per RFC 5869)                                                                                                          |
| `Fortuna`                                                           | `Generator` + `HashFn` (any compatible pair: `SerpentGenerator` / `ChaCha20Generator` / `AESGenerator` × `SHA256Hash` / `SHA3_256Hash` / `BLAKE3Hash`) |
| `Sign`                                                              | `SignStream` + `VerifyStream` (one-shot degenerates to single-chunk streaming) over any `SignatureSuite`                                               |
| `SignStream`, `VerifyStream`                                        | `StreamableSignatureSuite` (generic, caller provides suite); `createRunningHash` over a `PrehashAlgorithm`                                             |
| `Ed25519Suite`, `Ed25519PreHashSuite`                               | `Ed25519` (`_signInternalPk` / `_signPrehashedInternalPk` per call, `dispose()` in finally)                                                            |
| `EcdsaP256Suite`                                                    | `EcdsaP256` (`_signInternalPk` per call) + `SHA256` for streaming prehash                                                                              |
| `MlDsa{44,65,87}Suite`, `MlDsa{44,65,87}PreHashSuite`               | `MlDsa{44,65,87}` per call (`dispose()` in finally)                                                                                                    |
| `SlhDsa{128f,192f,256f}Suite`, `SlhDsa{128f,192f,256f}PreHashSuite` | `SlhDsa{128f,192f,256f}` per call                                                                                                                      |
| `MlDsa{44,65,87}SlhDsa{128f,192f,256f}Suite`                        | PQ-only hybrid: `MlDsa44/65/87` + `SlhDsa128f/192f/256f` at matched NIST categories; runs both verifies always                                         |
| `MlDsa{44,65}Ed25519Suite`                                          | Classical+PQ hybrid: `MlDsa44/65` + `Ed25519`; composite M' construction per draft-ietf-lamps-pq-composite-sigs §3.2                                   |
| `MlDsa{44,65}EcdsaP256Suite`                                        | Classical+PQ hybrid: `MlDsa44/65` + `EcdsaP256`; composite M' construction with ECDSA-internal SHA-256 per §6                                          |
| `MerkleVerifier`, `MerkleLog`, `SignedLog`                          | `Sha256Tree` or `Blake3Tree` + any `SignatureSuite` for cosignatures (Ed25519Suite or MlDsa44Suite shipping)                                           |

See [exports.md](./exports.md) for the complete export reference, including every class, function, type, per-module init function, and the `isInitialized` re-exports available from every subpath.

---

## NPM Package

**Subpath exports:**

```json
{
  "exports": {
    ".":                      "./dist/index.js",
    "./stream":               "./dist/stream/index.js",
    "./sign":                 "./dist/sign/index.js",
    "./merkle":               "./dist/merkle/index.js",
    "./ratchet":              "./dist/ratchet/index.js",
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
    "./mlkem":                "./dist/mlkem/index.js",
    "./mlkem/embedded":       "./dist/mlkem/embedded.js",
    "./mldsa":                "./dist/mldsa/index.js",
    "./mldsa/embedded":       "./dist/mldsa/embedded.js",
    "./slhdsa":               "./dist/slhdsa/index.js",
    "./slhdsa/embedded":      "./dist/slhdsa/embedded.js",
    "./blake3":               "./dist/blake3/index.js",
    "./blake3/embedded":      "./dist/blake3/embedded.js",
    "./ed25519":              "./dist/ed25519/index.js",
    "./ed25519/embedded":     "./dist/ed25519/embedded.js",
    "./x25519":               "./dist/x25519/index.js",
    "./x25519/embedded":      "./dist/x25519/embedded.js",
    "./ecdsa":                "./dist/ecdsa/index.js",
    "./ecdsa/embedded":       "./dist/ecdsa/embedded.js"
  }
}
```

> [!NOTE]
> Pool worker source files (`dist/serpent/pool-worker.js`, `dist/chacha20/pool-worker.js`, `dist/aes/pool-worker.js`) ship in the package but are not in the `exports` map. They are the build inputs from which `scripts/embed-workers.ts` produces the IIFE source strings embedded in `dist/<cipher>/cipher-suite.js` at lib build time. Workers are spawned from those embedded strings via classic blob URLs. Consumers do not import the `pool-worker.js` files directly, and bundlers do not need to chunk them. Strict-CSP consumers (`worker-src 'self'`, no `blob:`) can serve one of these files as their own same-origin worker by spread-overriding `createPoolWorker` on the cipher object; see [ciphersuite.md](./ciphersuite.md) for the pattern and [csp.md](./csp.md) for the policy.

The root `.` export re-exports everything. Subpath exports allow bundlers to tree-shake at the module level; a consumer importing only `./sha3` does not include the Serpent wrapper classes or their embedded WASM binaries in their bundle.

The `/embedded` subpaths provide gzip+base64 WASM blobs for zero-config usage. Consumers using URL-based or pre-compiled loading can skip the `/embedded` imports entirely, keeping them out of the bundle.

**Tree-shaking:** `"sideEffects": false` is set in `package.json`. Bundlers that support tree-shaking (webpack, Rollup, esbuild) can eliminate unused modules and their embedded WASM binaries from the final bundle.

**Published.** The NPM package includes:

- `dist/`: compiled JS, TypeScript declarations, WASM binaries, pool worker source files (build inputs, not runtime spawn entries; see the NOTE above), and a subset of consumer-facing API docs for offline use.
- `CLAUDE.md`: agent-facing project context.
- `SECURITY.md`: vulnerability disclosure policy.

**Not published.** `src/`, `test/`, `build/`, `scripts/`, `.github/`, editor configs.

---

## Test Suite

<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/testing.svg" alt="Test Suite data flow diagram" width="800">

### Structure

The `test/` directory contains three independent categories of files, used by separate workflows.

**Unit tests** (`unit/`) are Vitest suites that compile to a JS target for fast local iteration. The directory mirrors `src/ts/` structure with one folder per module, plus a handful of top-level `.test.ts` files for cross-cutting concerns (init, errors, utils, fortuna). CI splits these by domain via `unit-*.yml` for parallel execution.

**End-to-end tests** (`e2e/`) are Playwright suites that exercise the actual WASM artifacts across V8, SpiderMonkey, and JavaScriptCore. They run after the full build, including pool-worker bundling. Beyond cross-browser KAT replay (Monte Carlo reduced to 50 outer iterations versus 1200 in unit), the e2e tier exercises code paths the unit tier cannot reach: Fortuna's DOM entropy collector against synthesized mouse and keyboard events, all seven `WasmSource` loader types under a strict Content-Security-Policy page with no `unsafe-eval` and no `unsafe-inline` (plus the negative case proving `wasm-unsafe-eval` is required, and `SealStreamPool` worker behavior across `blob:` and same-origin factories per engine; see [csp.md](./csp.md)), primitive use and disposal inside a real `Web Worker`, multi-worker `SealStreamPool` with in-flight `destroy()` and dead-pool cascades on tampered ciphertext, large-chunk regression up to 5MB, SIMD throughput benchmarks per browser JS engine, and full lifecycle for the SPQR ratchet and `MerkleLog` + `MerkleVerifier`.

**Test vectors** (`vectors/`) is the immutable known-answer-test corpus. Files are read-only reference data. Some come from authoritative specifications (FIPS, RFCs, ACVP, NIST CAVP); others are self generated as regression vectors by `scripts/gen-*-vectors.ts`. CI validates KAT file integrity against `SHA256SUMS` and re-derives every Tier 2 byte against the [Rust verifier](./vector_audit.md) crate at `scripts/verify-vectors/` on every commit and PR.

See [test-suite.md](./test-suite.md) for the full testing methodology, vector corpus inventory with provenance, and gate discipline. See [vector_audit.md](./vector_audit.md) for the tier classification and verifier coverage.

### Coverage

Coverage falls into five buckets. Categories overlap, and many test files exercise more than one.

**Correctness against external authority**

- **KAT replay.** Direct verification against externally sourced reference vectors. Sources include NIST CAVP `.rsp` files, NIST ACVP, RFC test vectors, NESSIE, Wycheproof, the BLAKE3 team's `test_vectors.json`, transparency-dev/merkle, and c2sp.org worked examples.

- **Monte Carlo and multi-block.** Chained iterative tests, mostly the AESAVS §6.4 Monte Carlo and §6.3 Multi-block Message shapes, plus the Serpent ECB and CBC Monte Carlo corpora.

- **Spec algorithm trace.** Specific intermediates and algebraic identities checked against the spec. FIPS 197 §B, Round 1 intermediate state; Practical Cryptography §9.5.5, Fortuna pool-selection divisibility rule; RFC 6979 §3.2, deterministic K derivation; BLAKE3 §2.5, queue-per-level discipline; the ML-DSA NTT zetas table; NTT round-trip identity `invntt(ntt(p)) ≡ p (mod q)`; Edwards group laws.

**Implementation parity**

- **SIMD-vs-scalar.** SIMD kernels produce byte-identical output to their scalar counterparts across full input sweeps and boundary cases.

- **Streaming-vs-one-shot.** Streamed output matches one-shot output for deterministic suites byte for byte. For hedged suites, headers and payloads match exactly while only the trailing signature re-rolls.

- **Pool-vs-single-thread.** Pooled `SealStream` output is bit-identical to single-thread `SealStream` across the size sweep up to 5MB.

- **Dispatch coverage.** Test-only WASM invocation counters confirm the intended SIMD or batch path actually fires for inputs that should route through it, not silently falling back to scalar.

**Defensive and security**

- **Memory hygiene.** Scratch regions zero after every public op (keygen, sign, verify, encap, decap, hash, AEAD encrypt and decrypt). Wipe-on-auth-failure, wipe-before-reassign, and a wipe-ACK handshake on pool destroy. The pre-dirty-then-op pattern poisons regions with `0xa5` to prove wipe definitively zeros instead of leaving initial-empty buffers untouched.

- **Concurrency and exclusivity.** Per-module ownership tokens (`_assertNotOwned`), atomic-defense per WASM-touching method, init-race coalescing via the pending-promise cache, cross-module interleaving (e.g., SHAKE128 blocks MlKem768 ops).

- **State machine lifecycle.** Single-use guards, idempotent dispose, terminal `'failed'` state on crypto-path throws, post-dispose method-call rejection, double-finalize and update-after-finalize guards.

- **Constant-time invariants.** Branch-free `constantTimeEqual` with SIMD compare, timing-invariance sweeps for PKCS7 padding, fail-fast ordering on commitment checks so timing leaks cannot precede the commitment verdict.

- **Tamper rejection.** Byte flips on tag, ciphertext, AAD, IV, key, and signature; half-swaps for hybrid signatures; cross-suite forgery resistance; mid-stream tamper detection; replay and reorder.

**API contract**

- **Caller validation.** Wrong-length keys throw `RangeError`, wrong-type inputs throw `TypeError`, context strings over the spec cap throw documented `SigningError` discriminators. Verify-side returns `false` instead of throwing for structural mismatches.

- **Error-discriminator coverage.** Every `SigningError`, `AuthenticationError`, `MerkleLogError`, `KeyAgreementError`, and `MerkleCodecError` discriminator string is exercised on a real failure path.

- **Internal API surface.** `@internal` exports stay absent from `dist/*.d.ts` and `dist/*.js` across both the root barrel and submodules. The five v2.1.1-removed `_<module>Ready` probes are confirmed gone from every entry point.

**Wire format**

- **Envelope and blob KATs.** Pinned byte-exact vectors for v3 seal blobs, sealstream preambles, sign envelopes, signed-note envelopes, checkpoint bodies, and cosig payloads. Most are externally authoritative; a subset are self-generated tripwires for stability where no external authority exists.

- **Codec round-trips and strict parsing.** DER encode and decode (X.690 §8.3, INTEGER and §8.9, SEQUENCE), RFC 5915 §3, ECPrivateKey, RFC 9162 §2.1.3 and §2.1.4, inclusion and consistency proofs, plus the c2sp.org/signed-note and c2sp.org/tlog-checkpoint text codecs. Strict-parser rejection matrices cover non-minimal length encoding, wrong tags, trailing bytes, and leading-zero violations.

### Gate discipline

**Each primitive family has a gate test:** the simplest authoritative vector for that primitive. The gate must pass before any other tests in that family are written or run. Gate tests are annotated with a `// GATE` comment.

Three flavors appear in practice. **Substrate gates** lock the lowest layer of a primitive against the spec (`curve25519/gate.test.ts`, `p256/gate.test.ts`, `merkle/sha256-hasher-rfc6962-kat.test.ts`). **Primary gates** lock a single authoritative vector for the public API (the BLAKE3 empty-input KAT, the Serpent S-box table). **Per-implementation gates** lock byte-identity between two implementations of the same primitive (every SIMD kernel against its scalar reference, every streaming class against its one-shot counterpart).

See [test-suite.md](./test-suite.md) for the full list of gates per primitive family.

---

## Security

### Correctness Contract

leviathan-crypto must produce byte-identical output to the authoritative specification for every known test vector. Three independent verification layers cross-check every Tier 2 KAT: the leviathan TypeScript reference (a parallel codebase to the WASM stack), external tools (OpenSSL, Python hashlib, Node.js crypto) for primitives where parallel implementations exist, and the [Rust verifier](./vector_audit.md) crate at `scripts/verify-vectors/`, which re-derives every Tier 2 KAT byte from RustCrypto primitives sharing zero code with the WASM stack.

The vector corpus in `test/vectors/` acts as a source of immutable known-answer-test truth. KAT files are reference data from authoritative specifications (FIPS, RFCs, ACVP, NIST CAVP, NESSIE) or self generated as regression vectors by `scripts/gen-*-vectors.ts`. CI validates corpus integrity against `SHA256SUMS` on every run. See [test-suite.md](./test-suite.md) for the full corpus inventory, provenance, and gate discipline. See [vector_audit.md](./vector_audit.md) for the tier classification and verifier coverage.

#### `init()` contracts

The public `init()` API is gated by [`init.test.ts` and the `init/` test suite](./test-suite.md#unit-tests-vitest), which validate each `WasmSource` type, idempotency, partial-init isolation, alias resolution, pre-init-error contracts, and the internal API surface stripped from `dist/`.

#### Independent Rust verifier

The [Rust verifier](./vector_audit.md) crate at `scripts/verify-vectors/` is a third verification layer alongside the leviathan TypeScript reference and external tools (OpenSSL, Python hashlib, Node.js crypto). It re-derives every Tier 2 KAT byte from RustCrypto primitives that share zero code with the leviathan-crypto WASM stack, with pinned dependency versions and a pinned Rust toolchain. See [vector_audit.md](./vector_audit.md) for the full tier classification, [what the verifier proves](./vector_audit.md#what-the-verifier-proves), and the [CI integration](./vector_audit.md#ci-integration) covering the workflow DAG, cipher-target inventory, and runtime profile.

---

### Cryptanalytic margin

Implementation correctness is one axis; algorithmic strength is another. Each of the three ciphers carries a published cryptanalytic margin against the best known attack on the full construction.

**Serpent-256 is verified at 32 rounds with a wide margin.** The cipher placed second to Rijndael in the AES competition, rated higher on security margin and timing side-channel resistance but lower on 2001-era performance; that gap no longer matters on modern hardware. The best mathematical attack on the full cipher is biclique cryptanalysis at 2²⁵⁵·¹⁹ time with 2⁴ chosen ciphertexts, less than one bit faster than exhaustive key search. Independent research against this implementation improved the published result by −0.20 bits through systematic parameter search, confirming no structural weakness beyond what the literature describes ([BicliqueFinder](https://github.com/xero/BicliqueFinder/blob/main/biclique-research.md)). Reduced-round attacks reach 12 rounds (multidimensional linear), leaving a 20-round security margin, wider than AES-256's. No practical attack on full Serpent-256 is known.

**ChaCha20-Poly1305 has a 13-round margin.** The AEAD is IETF-standardized (RFC 8439) and descends from Salsa20 in the eSTREAM portfolio; it outperforms AES in software on platforms without hardware acceleration. The best published distinguisher reaches 7 of 20 rounds (Shi et al. 2012, differential-linear) and requires infeasible data; nothing further is published. Poly1305 forgery is bounded at ⌈l/16⌉/2¹⁰⁶ per message. XChaCha20's 192-bit nonce shifts the 50% collision boundary to 2⁹⁶ messages, beyond any realistic deployment. ChaCha20 is deployed at scale across TLS 1.3, WireGuard, Signal, and Android full-disk encryption with no known practical weaknesses in the full-round construction.

**AES-256-GCM-SIV has the narrowest published margin of the three** *but remains intact in practice.* The best mathematical attack on the full cipher is biclique cryptanalysis (Bogdanov, Khovratovich, & Rechberger 2011) at 2²⁵⁴·⁴ time with 2⁴⁰ chosen plaintexts, roughly 0.6 bits below exhaustive key search; differential and linear distinguishers bounded by the AES wide-trail strategy do not approach the full 14 rounds. The 2009 Biryukov-Khovratovich related-key boomerang reaches full AES-256 in 2⁹⁹·⁵ time but assumes attacker-chosen key relationships that AEAD use under independent KDF outputs does not provide. GCM-SIV adds nonce-misuse resistance over AES-GCM (RFC 8452, Gueron & Lindell 2015), so under nonce reuse an attacker learns only whether two encryptions shared identical inputs, with no key recovery and no universal forgery. AES is deployed at scale across TLS, IPsec, SSH, and FIPS-validated systems with no known practical weaknesses.

---

### Constant-time at the algorithm level

Three layers compose the library's constant-time posture: primitive algorithm choice, a single TypeScript routing point for secret-data equality, and a small set of named WASM-internal exceptions with published rationale.

#### Algorithm choice

**Every primitive is constant-time at the algorithm level.** The same code in C, Rust, or hand-typed assembly would have the same property. WebAssembly does not buy that; the implementation does. Serpent and AES use bitsliced Boolean-circuit S-boxes with no table lookups. ChaCha20's ARX construction (add, rotate, XOR) is branchless by construction. SHA-2 and SHA-3 round functions are pure arithmetic and pure bitwise permutation respectively. ML-KEM extends the same principle to post-quantum: the Fujisaki-Okamoto re-encryption uses dedicated `ct_verify` and `ct_cmov` primitives implemented in the ML-KEM WASM module that never pass through JavaScript.

#### TS-layer routing

**Every secret-data equality check in TypeScript routes through [`constantTimeEqual`](./utils.md#constanttimeequal)** from `src/ts/utils.ts`. That function is a thin wrapper over a dedicated SIMD WASM module (`src/asm/cte/`) that does branch-free v128 XOR-accumulate. There is no JavaScript fallback, runtimes without SIMD support throw at init. The routing rule is library-wide: AEAD tag verification (AES-GCM, AES-GCM-SIV, ChaCha20-Poly1305, XChaCha20-Poly1305), HMAC verification (Serpent's Encrypt-then-MAC), seal-layer key commitment, ML-DSA's c̃ comparison, and ML-KEM's public-key hash check all use the central path. The policy is enforced by comments at every call site (e.g. "no tag compare lives inside the AES module itself, this is library-wide policy for atomic AEADs") so the rule stays visible at the point of enforcement.

In-WASM equality checks inside other modules (mlkem FO transform, slhdsa PK.root, ed25519 / ecdsa pk-fault cross-check) cannot cross the JS boundary mid-computation and therefore cannot route through cte.wasm directly. They import `ctEqual` from `src/asm/cte/shared.ts` instead. The AS compiler inlines that helper into each importer's compile unit, so every module shares one audited algorithm without sharing a runtime binary.

#### Documented exceptions

Three primitives branch on secret-derived intermediate values. Each is documented at the source with rationale tied to a published spec section.

**GHASH / POLYVAL 4-bit-windowed multiply.** `src/asm/aes/gf128.ts`. The AES-GCM and AES-GCM-SIV authentication backends use a 256-byte 4-bit-windowed multiplication table indexed by secret-derived state. This is the same posture as BoringSSL, OpenSSL, and RustCrypto on hardware without PCLMULQDQ. WebAssembly does not currently expose carry-less multiply, so a fully table-free GHASH or POLYVAL is not implementable in this environment without unacceptable throughput cost. The library documents the leak surface, mitigates it with per-message authentication keys (the POLYVAL key in AES-GCM-SIV derives per nonce from the master, not fixed across the session), and recommends the AEAD `seal` family over the lower-level `AESGCM` primitive.

**ML-DSA `decompose` special-case branch.** `src/asm/mldsa/rounding.ts`. FIPS 204 Algorithm 36 line 3 takes a special-case branch when `a − r0 = q − 1`. The leak is the same statistical signal an attacker already gets from the SHAKE-driven rejection-restart loop in Algorithm 7 signing, each restart changes the SHAKE output and the iteration count is observable through coarser timing channels regardless. Documented per FIPS 204 §3.6.3.

**ML-DSA `poly_chknorm` early-exit.** `src/asm/mldsa/poly.ts`. The norm check (`‖z‖∞ < γ1 − β`, etc., per FIPS 204 §2.3) early-exits on the first coefficient that violates the bound. The leaked iteration count is the same signal already exposed by the rejection-restart pattern in signing, total signing time is observable regardless. Documented per FIPS 204 §2.3 and §3.6.3.

Neither ML-DSA exception is key-revealing. Both reveal statistical patterns the attacker already gets through coarser timing channels intrinsic to the rejection-sampling design.

---

### Implementation discipline

**Every primitive derives independently from its authoritative specification.** FIPS 180-4, FIPS 197, FIPS 202, FIPS 203, RFC 8439, RFC 8452, RFC 2104, RFC 5869, and the original Serpent paper. None is ported from an existing implementation. Published known-answer-test vectors (NIST CAVP, NESSIE, RFC appendices, and ACVP) are immutable. When an implementation produces wrong output, the implementation gets fixed and the vectors stay. New tests do not extend the surface until the existing surface gates green.

**Every primitive family has a gate test.** The gate is the simplest authoritative vector for that primitive, annotated `// GATE` and required to pass before any other test in the family runs. KAT files in `test/vectors/` come from spec authors directly (FIPS, RFC, ACVP, NIST CAVP, NESSIE), or `scripts/gen-*-vectors.ts` generates them as regression vectors. CI validates corpus integrity against SHA256SUMS on every run. Cross-implementation verification works in layers: the `verify-vectors` Rust crate re-runs every KAT against a parallel Rust implementation, leviathan's TypeScript reference provides a second independent codebase, and external tools (OpenSSL, Python hashlib, Node.js crypto) cross-check primitives where parallel implementations exist.

**Memory hygiene.** Every public cryptographic operation wipes its secret-derived scratch on the way out, including failure paths. AEAD authentication failures wipe before the exception propagates. Stateless AEADs are strict single-use; any throw from `encrypt()` terminates the instance. Stateful classes hold an exclusivity token on their backing WASM module. Cross-module operations assert non-ownership of the modules they touch. The high-level API surfaces (`Seal`, `SealStream`, `OpenStream`, `SealStreamPool`, and `MlKemSuite`) are authenticated by default with internally-managed nonces. The unauthenticated raw modes ship for power users and are not the recommended entry point.

**All streaming constructions satisfy the _Cryptographic Doom Principle_.** The MAC compare is the unconditional gate into the decrypt path. Serpent and XChaCha20 use verify-then-decrypt. The implementation checks the tag before materializing any plaintext. AES-GCM-SIV uses verify-then-release. The tag is a function of the plaintext, so the SIV construction reconstructs the plaintext in WASM linear memory, then recomputes and compares the tag in constant time. On mismatch, the implementation wipes the WASM-side plaintext before the throw, and only slices the plaintext across the WASM-to-JavaScript boundary after the auth check. In either path, forged ciphertext never reaches the caller as plaintext.

**The seal layer is key-committing across all three suites.** Serpent gets it natively from HMAC-SHA-256. XChaCha20 and AES-GCM-SIV add an explicit 32-byte commitment derived from the master key via HKDF-SHA-256 alongside the encryption key. The library verifies the commitment in constant time before processing any chunk. A wrong key fails fast, ahead of any call to Poly1305 or POLYVAL. The HKDF info string incorporates the full 20-byte header, so tampering with the format enum, framing flag, nonce, or chunk size produces different keys and fails on the first chunk. This closes the Invisible Salamanders attack surface for any higher-level construction built on the seal primitive.

#### Agentic development contracts

**All AI-assisted development on this repository operates under a strict agentic contract** defined in [AGENTS.md](https://github.com/xero/leviathan-crypto/blob/main/AGENTS.md). The contract enforces spec authority over planning documents, immutable test vectors, gate discipline before any test-suite extension, independent algorithm derivation from published standards, and constant-time and wipe requirements for all security-sensitive code paths. The contract explicitly prohibits agents from guessing cryptographic values or resolving spec ambiguities silently.

**Consumer agent guidance.** A [`CLAUDE.md`](./CLAUDE_consumer.md) file ships at the package root as a terse routing layer for AI consumer agents: high-level API entry points, cross-cutting foot-guns, and wiki URLs for per-primitive references. It does for consumer-side AI work what `AGENTS.md` does for contributor-side AI work.

---

### Threat model

The architecture above commits to a specific threat model. Three adversary classes act at different layers, a shared set of trust assumptions underlies all three, and a framing constraint bounds the whole.

**Runtime adversary.** This adversary has full chosen-ciphertext capability at the API surface, runs concurrent JavaScript in the same browser context, and reads WASM linear memory at any operation boundary. The library commits to AEAD confidentiality and integrity under correctly-generated keys, key commitment across all three suites, nonce-misuse resistance for AES-GCM-SIV, per-operation key wipes on success and failure paths, module-isolated linear memory, and forward-secret plus post-compromise primitives for session protocols built on the ratchet. The [defended attacks](#defended-attacks) inventory enumerates the specific threats. CPU-level side channels (Spectre-class, cache-timing on secret-dependent loads, branch prediction, speculative execution), JavaScript heap inspectors (intern pools, eval injection, prototype pollution), and physical access (DPA, EM analysis, fault injection) stay out of scope; [where defense ends](#where-defense-ends) covers the disclaim in detail.

**Construction adversary.** Spec drift enters through contributor mistakes, ported-from-another-implementation errors, or AI-assisted guesses and unstated assumptions. Defenses include independent derivation from authoritative spec, immutable KAT vectors with SHA256SUMS integrity validated in CI, gate discipline before any test-suite extension, cross-implementation verification across the `verify-vectors` Rust crate plus the TypeScript reference plus external tools, and the [agentic development contracts](#agentic-development-contracts) for AI-assisted work.

**Distribution adversary.** Typosquat variants of `leviathan-crypto` on NPM could otherwise install attacker-controlled code under a believable name. Decoy packages claim common variants preemptively, ahead of any observed attack; the [defended attacks](#defended-attacks) section describes the mechanism. Compromise of the NPM registry itself, and any supply-chain compromise downstream of the registry, stay out of scope.

**Trust assumptions.** Across all three axes the model assumes a faithful WebAssembly runtime, a working CSPRNG, the browser's same-origin and sandbox boundaries, and NPM publishing pipeline integrity. Keys must be properly generated; Argon2id, if used, must be consumer-installed. Consumer code must use the API as documented, with the published [wiki](https://github.com/xero/leviathan-crypto/wiki) and supporting documentation.

**Framing constraint.** The whole model lives inside a JavaScript runtime. Side-channel resistance comparable to a native binary with hand-tuned instruction scheduling is not promised; the [honest comparison](#the-honest-comparison) section is explicit about this trade-off.

---

### Defended attacks

The architectural defenses compose into protection against specific named attacks and DoS classes. The inventory below pairs each threat with its mechanism, split between runtime adversaries operating against a deployed instance and distribution adversaries operating on the NPM namespace.

#### Runtime

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

#### Distribution

**Typosquatting.** Misspellings or punctuation variants of `leviathan-crypto` on NPM could otherwise install attacker-controlled code under a believable name. Decoy packages cover common typosquat variants (missing hyphens, character transpositions, and common misspellings); each declares the real `leviathan-crypto` as an optional peer dependency and runs a post-install script that loudly warns the user with the correct package name and install command.

---

### Where defense ends

**WebAssembly is not constant time at the CPU level.** The native code the WASM JIT emits runs on a real CPU with a real branch predictor, real cache hierarchy, and real speculative execution. WebAssembly itself has no language-level constant-time guarantee in its specification; the spec defines semantics, not timing. *WASM does not protect against Spectre-class side channels.*

**The browser sandbox restricts JavaScript-side measurement primitives that an in-page attacker would otherwise use to instrument these channels.** SharedArrayBuffer requires COOP/COEP headers; `performance.now()` is throttled; the cross-origin attacker has limited reach. The channels themselves remain. They are the runtime's and the hardware's responsibility.

**Cycle-equivalent timing across hardware is out of scope.** Different CPUs have different multiply latencies, cache geometries, and speculation behaviors. WASM does not equalize them. Defense against power analysis, electromagnetic emissions, fault injection, or physical device access is not in this library's threat model.

**The defended threat is concrete.** An adversary with read access to WASM linear memory between operations cannot recover key material from previously-completed operations. Authentication failures cannot disclose plaintext to JavaScript callers. Tampered headers, reordered chunks, spliced streams, and cross-stream substitutions fail authentication before decryption. Backward seeks on a decrypting stream throw rather than reuse a consumed counter nonce against new ciphertext. A wrong key under the seal API fails before the AEAD ever runs. Forged ciphertext never returns plaintext bytes to the caller.

**The undefended threats are equally concrete.** JavaScript-side memory disclosure from heap-snapshot exfiltration, eval injection, or prototype pollution is the runtime's responsibility. Host CPU side channels (cache timing on secret-dependent loads, branch prediction, and speculative execution) are the hardware's. Physical device access is the deployment's. Supply chain compromise downstream of the NPM registry is the consumer's. None of these is what the library claims to address.

---

### The honest comparison

**leviathan-crypto is for cryptography that runs inside a JavaScript runtime.** Within that constraint, this library offers the strongest posture available: algorithm-level constant-time ciphers, per-operation wipe hygiene, module-isolated linear memory, and predictable JIT-lowered native code.

**But the constraints matter.** The JavaScript runtime is a weaker side-channel environment than a native binary with hand-tuned instruction scheduling, no matter the strength of the cryptographic algorithms used. Leviathan is for pure web deployments. If side-channel resistance is critical to your threat model and you're already shipping native code, a native crypto implementation is a better choice.

 _Our cipher choices, implementation discipline, and deployment vehicle collectively form leviathan-crypto, a library delivering disciplined cryptography to the browser. Our security claims are achieved not by any single element, but by their combination._

---

### Known Limitations

- **`SerpentCbc` is unauthenticated.** Use [`Seal`](./aead.md) with `SerpentCipher` for authenticated Serpent encryption, or pair [`SerpentCbc`](./serpent.md#serpentcbc) with [`HMAC_SHA256`](./sha2.md#hmac_sha256) (Encrypt-then-MAC) if direct CBC access is required.
- **Single-threaded WASM per instance.** One WASM instance per binary per thread. [`SealStreamPool`](./aead.md#sealstreampool) provides Worker-based parallelism for all three cipher families (Serpent, ChaCha20, AES); other primitives remain single-threaded.
- **Max input per WASM call.** CTR accepts at most 65536 bytes per call; CBC accepts at most 65552 bytes (65536 + 16 bytes PKCS7 maximum overhead). Wrappers handle splitting automatically for larger inputs.
- **WASM is not constant time at the CPU level.** Spectre-class side channels, cache-timing on secret-dependent loads, branch prediction, and speculative execution stay outside this library's threat model; they are the runtime's and the hardware's responsibility. See [Where defense ends](#where-defense-ends) for the full disclaim. The one documented constant-time exception inside the algorithm-level layer is the GHASH/POLYVAL 4-bit-windowed multiply table (256 bytes, indexed by secret-derived state) used by AES-GCM and AES-GCM-SIV; this matches the BoringSSL/OpenSSL/RustCrypto posture on hardware without PCLMULQDQ. The library mitigates the leak surface by deriving the POLYVAL authentication key per nonce in AES-GCM-SIV (RFC 8452 §4) and recommends the [AEAD](./aead.md#seal) `seal` family over the lower-level [`AESGCM`](./aes.md#aesgcm) primitive.

---

## Cross-References

| Document                               | Description                                                                                             |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| [index](./README.md)                   | Project documentation index                                                                             |
| [lexicon](./lexicon.md)                | Glossary of cryptographic terms                                                                         |
| [authenticated encryption](./aead.md)  | `Seal`, `SealStream`, `OpenStream`, `SealStreamPool`: cipher-agnostic AEAD APIs over any `CipherSuite`  |
| [development](./development.md)        | Day-to-day developer workflow: build, test, lint commands and the iteration loop                        |
| [examples](./examples.md)              | Code examples for every primitive                                                                       |
| [exports](./exports.md)                | Complete export reference: every class, function, and type                                              |
| [init](./init.md)                      | `init()` API, `WasmSource`, and idempotent behavior                                                     |
| [loader](./loader.md)                  | Internal WASM binary loading strategies                                                                 |
| [cipher suite](./ciphersuite.md)       | `CipherSuite` interface, `SerpentCipher`, `XChaCha20Cipher`, `AESGCMSIVCipher`, `MlKemSuite`            |
| [signing](./signing.md)                | `Sign`, `SignStream`, `VerifyStream`, envelope wire format, `SigningError`                              |
| [signature suite](./signaturesuite.md) | `SignatureSuite` interface plus the full ML-DSA / SLH-DSA / Ed25519 / ECDSA-P256 / hybrid catalog       |
| [test suite](./test-suite.md)          | Testing methodology, vector corpus, and gate discipline                                                 |
| [types](./types.md)                    | Public TypeScript interfaces and `CipherSuite`                                                          |
| [utils](./utils.md)                    | Encoding helpers, `constantTimeEqual`, `wipe`, `randomBytes`                                            |
| [audits](./audits.md)                  | Audit index: per-primitive correctness reviews                                                          |
| [vector_audit](./vector_audit.md)      | Test-vector tier classification, verifier coverage, and provenance of pinned vectors                    |
| [wasm](./wasm.md)                      | WebAssembly primer: modules, instances, memory, and the init gate                                       |
