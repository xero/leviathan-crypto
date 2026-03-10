# leviathan-crypto Documentation

API reference and implementation documentation for all modules in the library.

---

## Getting Started

- [index.md](./index.md): Library overview, quick start, and complete export reference
- [architecture.md](./architecture.md): Architecture overview, build pipeline, and module relationships
- [init.md](./init.md): `init()` API and WASM loading modes

---

## API Reference

### Serpent-256

| Module | Description |
|--------|-------------|
| [serpent.md](./serpent.md) | TypeScript API -- `Serpent`, `SerpentCtr`, `SerpentCbc` classes |
| [asm_serpent.md](./asm_serpent.md) | WASM implementation -- bitslice S-boxes, key schedule, CTR/CBC modes |
| [serpent_reference.md](./serpent_reference.md) | Algorithm specification -- S-boxes, linear transform, round structure, known attacks |
| [serpent_audit.md](./serpent_audit.md) | Security audit -- correctness verification, side-channel analysis, cryptanalytic paper review |

### ChaCha20 / Poly1305

| Module | Description |
|--------|-------------|
| [chacha20.md](./chacha20.md) | TypeScript API -- `ChaCha20`, `Poly1305`, `ChaCha20Poly1305`, `XChaCha20Poly1305` |
| [asm_chacha.md](./asm_chacha.md) | WASM implementation -- quarter-round, Poly1305 accumulator, HChaCha20 |

### SHA-2

| Module | Description |
|--------|-------------|
| [sha2.md](./sha2.md) | TypeScript API -- `SHA256`, `SHA512`, `SHA384`, `HMAC_SHA256`, `HMAC_SHA512`, `HMAC_SHA384` |
| [asm_sha2.md](./asm_sha2.md) | WASM implementation -- compression functions, HMAC inner/outer padding |

### SHA-3

| Module | Description |
|--------|-------------|
| [sha3.md](./sha3.md) | TypeScript API -- `SHA3_224`, `SHA3_256`, `SHA3_384`, `SHA3_512`, `SHAKE128`, `SHAKE256` |
| [asm_sha3.md](./asm_sha3.md) | WASM implementation -- Keccak-f[1600] permutation, sponge construction |

### Fortuna CSPRNG

| Module | Description |
|--------|-------------|
| [fortuna.md](./fortuna.md) | `Fortuna` -- CSPRNG with forward secrecy, 32 entropy pools, browser + Node.js collectors |

### Utilities & Types

| Module | Description |
|--------|-------------|
| [utils.md](./utils.md) | Encoding helpers, `constantTimeEqual`, `wipe`, `randomBytes` -- no `init()` required |
| [types.md](./types.md) | TypeScript interfaces -- `Hash`, `KeyedHash`, `Blockcipher`, `Streamcipher`, `AEAD` |

### Internal

| Module | Description |
|--------|-------------|
| [init.md](./init.md) | `init()` function, module cache, three loading modes |
| [loader.md](./loader.md) | WASM binary loading -- embedded (base64), streaming (fetch), manual |

---

## Project Documentation

| Document | Description |
|----------|-------------|
| [architecture.md](./architecture.md.md) | repository structure, architecture diagram, build pipeline, module relationships, buffer layouts, correctness contract, limitations, etc |
| [testing.md](./testing.md) | Test suite structure, vector corpus, gate discipline |
| [serpent_audit.md](./serpent_audit.md) | Report of our serpent implementation security and correctness audit |
| [serpent_reference.md](./serpent_reference.md) | Serpent algorithm overview |
| [branding.md](./branding.md) | Project artwork and other PR materials |
