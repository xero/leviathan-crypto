# Leviathan Crypto Library Documentation Index

## Getting Started

| Document | Description |
|----------|-------------|
| [examples.md](./examples.md) | Code examples for every primitive |
| [cdn.md](./cdn.md) | CDN usage examples. _"no bundler? no problem"_ |
| [exports.md](./exports.md) | Comprehensive export reference detailing each class, function, and type |
| [init.md](./init.md) | `init()` API, `WasmSource`, subpath imports, tree-shaking |
| [loader.md](./loader.md) | WASM binary loading: `WasmSource` type dispatch, `loadWasm()`, `compileWasm()` |

---

## API Reference

### Serpent-256

| Module | Description |
|--------|-------------|
| [serpent.md](./serpent.md) | TypeScript API: `SerpentCipher`, `Serpent`, `SerpentCtr`, `SerpentCbc` |
| [asm_serpent.md](./asm_serpent.md) | WASM implementation: bitslice S-boxes, key schedule, CTR/CBC modes |

### XChaCha20 / Poly1305

| Module | Description |
|--------|-------------|
| [chacha20.md](./chacha20.md) | TypeScript API: `ChaCha20`, `Poly1305`, `ChaCha20Poly1305`, `XChaCha20Poly1305`, `XChaCha20Cipher` |
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
| [asm_sha3.md](./asm_sha3.md) | WASM implementation: Keccak permutation (1600-bit state), sponge construction |

### ML-KEM (Post-Quantum KEM)

| Module | Description |
|--------|-------------|
| [kyber.md](./kyber.md) | TypeScript API: `MlKem512`, `MlKem768`, `MlKem1024`, `KyberSuite` |

### Streaming AEAD

| Module | Description |
|--------|-------------|
| [stream.md](./stream.md) | `Seal`, `SealStream`, `OpenStream`, `SealStreamPool`: one-shot and streaming cipher-agnostic AEAD |

### Fortuna CSPRNG

| Module | Description |
|--------|-------------|
| [fortuna.md](./fortuna.md) | `Fortuna`: CSPRNG with forward secrecy, 32 entropy pools, browser + Node.js collectors |

### Utilities & Types

| Module | Description |
|--------|-------------|
| [utils.md](./utils.md) | Encoding helpers, `constantTimeEqual`, `wipe`, `randomBytes`, `hasSIMD` _no `init()` required_ |
| [types.md](./types.md) | TypeScript interfaces: `Hash`, `KeyedHash`, `Blockcipher`, `Streamcipher`, `AEAD` |

---

## Performance

| Document | Description |
|----------|-------------|
| [serpent_simd_bench.md](./serpent_simd_bench.md) | Serpent-256 SIMD benchmark results: CTR and CBC-decrypt inter-block 4-wide, scalar vs SIMD across V8, SpiderMonkey, and JSC |
| [chacha_simd_bench.md](./chacha_simd_bench.md) | ChaCha20 SIMD benchmark results: 4-wide inter-block parallelism, scalar vs SIMD across V8, SpiderMonkey, and JSC. Includes documented negative result for intra-block approach |

## Algorithm Correctness and Verifications

| Primitive | Audit Description |
|-----------|-------------------|
| [serpent_audit.md](./serpent_audit.md) | Correctness verification, side-channel analysis, cryptanalytic attack paper review |
| [chacha_audit.md](./chacha_audit.md) | XChaCha20-Poly1305 correctness, Poly1305 field arithmetic, HChaCha20 nonce extension |
| [sha2_audit.md](./sha2_audit.md) | SHA-256/512/384 correctness, HMAC and HKDF composition, constant verification |
| [sha3_audit.md](./sha3_audit.md) | Keccak permutation correctness, θ/ρ/π/χ/ι step verification, round constant derivation |
| [hmac_audit.md](./hmac_audit.md) | HMAC-SHA256/512/384 construction, key processing, RFC 4231 vector coverage |
| [hkdf_audit.md](./hkdf_audit.md) | HKDF extract-then-expand, info field domain separation, stream key derivation |
| [kyber_audit.md](./kyber_audit.md) | ML-KEM (FIPS 203) implementation audit: NTT correctness, IND-CCA2 decapsulation, NIST KAT coverage |

## Project Documentation

| Document | Description |
|----------|-------------|
| [architecture.md](./architecture.md) | Repository structure, architecture diagram, build pipeline, module relationships, buffer layouts, correctness contract, limitations |
| [test-suite.md](./test-suite.md) | Test suite structure, vector corpus, gate discipline |
| [serpent_reference.md](./serpent_reference.md) | Serpent algorithm: S-boxes, linear transform, round structure, known attacks |
| [wasm.md](./wasm.md) | WebAssembly primer in the context of this library |
| [argon2id.md](./argon2id.md) | Key derivation and password hashing with Argon2id alongside Leviathan primitives |
| [branding.md](./branding.md) | Project artwork and branding materials |

