<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### Leviathan Crypto Library Documentation Index

This index lists every documentation file in the `docs/` directory. Use it as your starting point for the API reference, architecture notes, benchmarks, and correctness audits.

> ### Table of Contents
> - [Getting Started](#getting-started)
> - [API Reference](#api-reference)
> - [Project Documentation](#project-documentation)
> - [Performance](#performance)
> - [Algorithm Correctness](#algorithm-correctness)

---

## Getting Started

| Document | Description |
|----------|-------------|
| [development.md](./development.md) | Day-to-day developer workflow: build, test, lint commands and the iteration loop |
| [examples.md](./examples.md) | Code examples for every primitive |
| [cdn.md](./cdn.md) | Use leviathan-crypto directly from a CDN with no bundler |
| [exports.md](./exports.md) | Complete export reference: every class, function, and type |
| [init.md](./init.md) | `init()` API, `WasmSource`, subpath imports, tree-shaking |
| [loader.md](./loader.md) | WASM binary loading internals: `WasmSource` dispatch, `loadWasm()`, `compileWasm()` |

---

## API Reference

### Authenticated Encryption

| Module | Description |
|--------|-------------|
| [aead.md](./aead.md) | `Seal`, `SealStream`, `OpenStream`, `SealStreamPool`, `SerpentCipher`, `XChaCha20Cipher`, `KyberSuite` |
| [ciphersuite.md](./ciphersuite.md) | `CipherSuite` interface and the in-tree symmetric / hybrid cipher consts |

### Signatures

| Module | Description |
|--------|-------------|
| [signaturesuite.md](./signaturesuite.md) | `SignatureSuite`, `Sign`, `SignStream`, `VerifyStream`, plus the shipped suite catalog and reserved entries |

### Post-Quantum KEM

| Module | Description |
|--------|-------------|
| [kyber.md](./kyber.md) | `MlKem512`, `MlKem768`, `MlKem1024`, `KyberSuite`: ML-KEM key encapsulation (FIPS 203) |

### Classical Signatures and Key Agreement

| Module | Description |
|--------|-------------|
| [ed25519.md](./ed25519.md) | `Ed25519`: classical Ed25519 signatures (RFC 8032), pure and Ed25519ph prehash modes |
| [x25519.md](./x25519.md) | `X25519`: Curve25519 Diffie-Hellman key agreement (RFC 7748) |
| [ecdsa-p256.md](./ecdsa-p256.md) | `EcdsaP256`, `EcdsaP256Suite`, `ecdsaSignatureToDer` / `ecdsaSignatureFromDer`: classical ECDSA signatures over NIST P-256 (FIPS 186-5 §6), hedged-by-default per `draft-irtf-cfrg-det-sigs-with-noise-05`, low-S enforced |
| [asm_curve25519.md](./asm_curve25519.md) | WASM implementation: field arithmetic, edwards25519, Montgomery ladder, scalar mod L, embedded SHA-512 |
| [asm_p256.md](./asm_p256.md) | p256 WASM implementation: GF(p256) field arithmetic, Renes-Costello-Batina 2016 complete addition, constant-time scalar mult, embedded SHA-256 + HMAC-SHA-256 for RFC 6979 K derivation |

### Post-Quantum Signatures

| Module | Description |
|--------|-------------|
| [mldsa.md](./mldsa.md) | `MlDsa44`, `MlDsa65`, `MlDsa87`: ML-DSA digital signatures (FIPS 204), pure mode and HashML-DSA |
| [slhdsa.md](./slhdsa.md) | `SlhDsa128f`, `SlhDsa192f`, `SlhDsa256f`: SLH-DSA hash-based signatures (FIPS 205), pure mode and HashSLH-DSA |

### Post-Quantum Ratchet

| Module | Description |
|--------|-------------|
| [ratchet.md](./ratchet.md) | `ratchetInit`, `KDFChain`, `kemRatchetEncap`, `kemRatchetDecap`: Sparse Post-Quantum Ratchet KDF primitives (DR spec §5 + §7.2) |

### AES (FIPS 197)

| Module | Description |
|--------|-------------|
| [aes.md](./aes.md) | TypeScript API: `AES`, `AESCbc`, `AESCtr`, `AESGCM`, `AESGCMSIV`, `AESGenerator`, `AESGCMSIVCipher` |
| [asm_aes.md](./asm_aes.md) | WASM implementation: bitsliced 8-block kernel, Canright tower-field S-box, CBC/CTR/GCM/GCM-SIV modes |

### Serpent-256

| Module | Description |
|--------|-------------|
| [serpent.md](./serpent.md) | TypeScript API: `Serpent`, `SerpentCtr`, `SerpentCbc` |
| [asm_serpent.md](./asm_serpent.md) | WASM implementation: bitslice S-boxes, key schedule, CTR/CBC modes |

### XChaCha20 / Poly1305

| Module | Description |
|--------|-------------|
| [chacha20.md](./chacha20.md) | TypeScript API: `ChaCha20`, `Poly1305`, `ChaCha20Poly1305`, `XChaCha20Poly1305` |
| [asm_chacha.md](./asm_chacha.md) | WASM implementation: quarter-round, Poly1305 accumulator, HChaCha20 |

### SHA-2

| Module | Description |
|--------|-------------|
| [sha2.md](./sha2.md) | TypeScript API: `SHA256`, `SHA512`, `SHA384`, `HMAC_SHA256`, `HMAC_SHA384`, `HMAC_SHA512`, `HKDF_SHA256`, `HKDF_SHA512` |
| [asm_sha2.md](./asm_sha2.md) | WASM implementation: compression functions, HMAC inner/outer padding |

### SHA-3

| Module | Description |
|--------|-------------|
| [sha3.md](./sha3.md) | TypeScript API: `SHA3_224`, `SHA3_256`, `SHA3_384`, `SHA3_512`, `SHAKE128`, `SHAKE256` |
| [kmac.md](./kmac.md) | TypeScript API: `CSHAKE128`, `CSHAKE256`, `KMAC128`, `KMAC256`, `KMACXOF128`, `KMACXOF256` (SP 800-185) |
| [asm_sha3.md](./asm_sha3.md) | WASM implementation: Keccak permutation (1600-bit state), sponge construction |

### Fortuna CSPRNG

| Module | Description |
|--------|-------------|
| [fortuna.md](./fortuna.md) | `Fortuna`: CSPRNG with forward secrecy and 32 entropy pools |

### Utilities and Types

| Module | Description |
|--------|-------------|
| [utils.md](./utils.md) | `randomBytes`, `constantTimeEqual`, `wipe`, encoding helpers. No `init()` required |
| [types.md](./types.md) | TypeScript interfaces: `Hash`, `KeyedHash`, `Blockcipher`, `Streamcipher`, `AEAD` |

---

## Project Documentation

| Document | Description |
|----------|-------------|
| [architecture.md](./architecture.md) | Repository structure, build pipeline, module relationships, buffer layouts, and correctness contract |
| [test-suite.md](./test-suite.md) | Test suite structure, vector corpus, and gate discipline |
| [Security Policy](./security_policy.md) | Security posture and vulnerability disclosure details |
| [lexicon](./lexicon.md) | Glossary of cryptographic terms |
| [wasm.md](./wasm.md) | WebAssembly primer in the context of this library |
| [argon2id.md](./argon2id.md) | Passphrase-based encryption using Argon2id alongside leviathan primitives |
| [serpent_reference.md](./serpent_reference.md) | Serpent algorithm: S-boxes, linear transform, round structure, known attacks |
| [chacha_reference.md](./chacha_reference.md) | ChaCha20 algorithm: ARX, block function, Poly1305 MAC, HChaCha20 subkeys, XChaCha20-Poly1305 AEAD, known attacks |
| [branding.md](./branding.md) | Project artwork and branding materials |

---

## Performance

See the [benchmark index](./benchmarks.md) for full results across V8, SpiderMonkey, and JavaScriptCore.

| Document | Description |
|----------|-------------|
| [benchmarks.md](./benchmarks.md) | Benchmark index |
| [serpent_simd_bench.md](./serpent_simd_bench.md) | Serpent-256 CTR and CBC-decrypt: scalar vs 4-wide SIMD across V8, SpiderMonkey, and JSC |
| [chacha_simd_bench.md](./chacha_simd_bench.md) | ChaCha20 4-wide inter-block parallelism: scalar vs SIMD across all three engines. Includes documented negative result for intra-block approach |

---

## Algorithm Correctness

See the [audit index](./audits.md) for a summary of all reviews.

| Primitive | Description |
|-----------|-------------|
| [audits.md](./audits.md) | Audit index |
| [serpent_audit.md](./serpent_audit.md) | Correctness verification, side-channel analysis, cryptanalytic attack paper review |
| [chacha_audit.md](./chacha_audit.md) | XChaCha20-Poly1305 correctness, Poly1305 field arithmetic, HChaCha20 nonce extension |
| [sha2_audit.md](./sha2_audit.md) | SHA-256/512/384 correctness, HMAC and HKDF composition, constant verification |
| [sha3_audit.md](./sha3_audit.md) | Keccak permutation correctness, step verification, round constant derivation |
| [hmac_audit.md](./hmac_audit.md) | HMAC construction, key processing, RFC 4231 vector coverage |
| [hkdf_audit.md](./hkdf_audit.md) | HKDF extract-then-expand, info field domain separation, stream key derivation |
| [kyber_audit.md](./kyber_audit.md) | ML-KEM FIPS 203 correctness, NTT verification, FO transform CT analysis, ACVP validation |
| [mldsa_audit.md](./mldsa_audit.md) | ML-DSA FIPS 204 prehashed-input surface audit |
| [slhdsa_audit.md](./slhdsa_audit.md) | SLH-DSA FIPS 205 implementation audit, including PQ-only hybrid factory invariants |
| [ed25519_audit.md](./ed25519_audit.md) | Ed25519 RFC 8032 plus FIPS 186-5 strict verification, fault-injection defence, embedded SHA-512 integrity, dom2 prehash binding |
| [x25519_audit.md](./x25519_audit.md) | X25519 RFC 7748 clamping discipline, constant-time Montgomery ladder, TS-layer all-zero rejection |
| [ecdsa-p256_audit.md](./ecdsa-p256_audit.md) | ECDSA-P256 FIPS 186-5 strict verification, RFC 6979 deterministic-K gate, hedged-by-default posture, low-S enforcement, fault-injection defence, embedded SHA-256 / HMAC-SHA-256 integrity |
| [stream_audit.md](./stream_audit.md) | Streaming AEAD composition, counter nonce binding, final-chunk detection, key wipe paths |
| [ratchet_audit.md](./ratchet_audit.md) | SPQR KDF primitives: HKDF parameter assignments, wipe coverage, counter encoding, direction slot alignment |
