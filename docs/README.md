# Leviathan Crypto Library

```
  ██     ▐█████ ██     ▐█▌  ▄█▌   ███▌ ▀███████▀▄██▌  ▐█▌  ███▌    ██▌   ▓▓
 ▐█▌     ▐█▌    ▓█     ▐█▌  ▓██  ▐█▌██    ▐█▌   ███   ██▌ ▐█▌██    ▓██   ██
 ██▌     ░███   ▐█▌    ██   ▀▀   ██ ▐█▌   ██   ▐██▌   █▓  ▓█ ▐█▌  ▐███▌  █▓
 ██      ██     ▐█▌    █▓  ▐██  ▐█▌  █▓   ██   ▐██▄▄ ▐█▌ ▐█▌  ██  ▐█▌██ ▐█▌
▐█▌     ▐█▌      ██   ▐█▌  ██   ██   ██  ▐█▌   ██▀▀████▌ ██   ██  ██ ▐█▌▐█▌
▐▒▌     ▐▒▌      ▐▒▌  ██   ▒█   ██▀▀▀██▌ ▐▒▌   ▒█    █▓░ ▒█▀▀▀██▌ ▒█  ██▐█
█▓ ▄▄▓█ █▓ ▄▄▓█   ▓▓ ▐▓▌  ▐▓▌  ▐█▌   ▐▒▌ █▓   ▐▓▌   ▐▓█ ▐▓▌   ▐▒▌▐▓▌  ▐███
▓██▀▀   ▓██▀▀      ▓█▓█   ▐█▌  ▐█▌   ▐▓▌ ▓█   ▐█▌   ▐█▓ ▐█▌   ▐▓▌▐█▌   ██▓
                    ▓█                               ▀▀        ▐█▌▌▌
```

Web cryptography built on Serpent-256 paranoia and XChaCha20-Poly1305 elegance.

---

## Quick Start

```bash
bun i leviathan-crypto
# or npm
npm install leviathan-crypto
```

```typescript
import { init, SerpentSeal, randomBytes } from 'leviathan-crypto'

await init(['serpent', 'sha2'])

const key = randomBytes(64)
const seal = new SerpentSeal()

const ciphertext = seal.encrypt(key, plaintext)
const decrypted  = seal.decrypt(key, ciphertext) // throws on tamper

seal.dispose()
```

For more: streaming, chunking, hashing, key derivation, and both ciphers: see the [examples](./examples.md) page.

---

## Getting Started

| Document | Description |
|----------|-------------|
| [architecture.md](./architecture.md) | Architecture overview, build pipeline, module relationships, buffer layouts |
| [init.md](./init.md) | `init()` API, three loading modes, subpath imports, tree-shaking |
| [wasm.md](./wasm.md) | WebAssembly primer in the context of this library |
| [examples.md](./examples.md) | Code examples for every primitive |
| [exports.md](./exports.md) | Comprehensive export reference detailing each class, function, and type |

---

## API Reference

### Serpent-256

| Module | Description |
|--------|-------------|
| [serpent.md](./serpent.md) | TypeScript API: `SerpentSeal`, `SerpentStream`, `SerpentStreamPool`, `SerpentStreamSealer`, `SerpentStreamOpener`, `Serpent`, `SerpentCtr`, `SerpentCbc` |
| [asm_serpent.md](./asm_serpent.md) | WASM implementation: bitslice S-boxes, key schedule, CTR/CBC modes |

### XChaCha20 / Poly1305

| Module | Description |
|--------|-------------|
| [chacha20.md](./chacha20.md) | TypeScript API: `ChaCha20`, `Poly1305`, `ChaCha20Poly1305`, `XChaCha20Poly1305` |
| [chacha20_pool.md](./chacha20_pool.md) | `XChaCha20Poly1305Pool`: parallel worker pool for authenticated encryption |
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

### Fortuna CSPRNG

| Module | Description |
|--------|-------------|
| [fortuna.md](./fortuna.md) | `Fortuna`: CSPRNG with forward secrecy, 32 entropy pools, browser + Node.js collectors |

### Utilities & Types

| Module | Description |
|--------|-------------|
| [utils.md](./utils.md) | Encoding helpers, `constantTimeEqual`, `wipe`, `randomBytes` _no `init()` required_ |
| [types.md](./types.md) | TypeScript interfaces: `Hash`, `KeyedHash`, `Blockcipher`, `Streamcipher`, `AEAD` |

### Internal

| Module | Description |
|--------|-------------|
| [loader.md](./loader.md) | WASM binary loading: embedded (base64), streaming (fetch), manual |

---

## Project Documentation

| Document | Description |
|----------|-------------|
| [architecture.md](./architecture.md) | Repository structure, architecture diagram, build pipeline, module relationships, buffer layouts, correctness contract, limitations |
| [test-suite.md](./test-suite.md) | Test suite structure, vector corpus, gate discipline |
| [serpent_reference.md](./serpent_reference.md) | Serpent algorithm: S-boxes, linear transform, round structure, known attacks |
| [wasm.md](./wasm.md) | WebAssembly primer in the context of this library |
| [argon2id.md](./argon2id.md) | Key derivation and password hashing with Argon2id alongside Leviathan primitives |
| [branding.md](./branding.md) | Project artwork and branding materials |

---

## Algorithm Correctness and Verifications

| Primitive | Audit Description |
|-----------|-------------------|
| [serpent_audit.md](./serpent_audit.md) | Correctness verification, side-channel analysis, cryptanalytic attack paper review |
| [chacha_audit.md](./chacha_audit.md) | XChaCha20-Poly1305 correctness, Poly1305 field arithmetic, HChaCha20 nonce extension |
| [sha2_audit.md](./sha2_audit.md) | SHA-256/512/384 correctness, HMAC and HKDF composition, constant verification |
| [sha3_audit.md](./sha3_audit.md) | Keccak permutation correctness, θ/ρ/π/χ/ι step verification, round constant derivation |
| [hmac_audit.md](./hmac_audit.md) | HMAC-SHA256/512/384 construction, key processing, RFC 4231 vector coverage |
| [hkdf_audit.md](./hkdf_audit.md) | HKDF extract-then-expand, info field domain separation, SerpentStream key derivation |

## Demos

| Name             | Link                                       | Code                                                              | Docs                                                                        | Description                                                                                                                                                                                             |
| ---------------- | ------------------------------------------ | ----------------------------------------------------------------- | --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`lvthn-web`**  | [▼](https://leviathan.3xi.club/web)        | [🛈](https://github.com/xero/leviathan-demos/tree/main/lvthn-web)  | [¶](https://github.com/xero/leviathan-demos/blob/main/lvthn-web/README.md)  | Encrypt text or files using Serpent-256-CBC and Argon2id key derivation from a single local html file, with armored output. No server, installation, or network connection required after initial load. |
| **`lvthn-chat`** | [▼](https://leviathan.3xi.club/chat)       | [🛈](https://github.com/xero/leviathan-demos/tree/main/lvthn-chat) | [¶](https://github.com/xero/leviathan-demos/blob/main/lvthn-chat/README.md) | End-to-end encrypted chat featuring two-party messaging over X25519 key exchange and XChaCha20-Poly1305 message encryption. Relay server functions as a dumb WebSocket pipe never seeing plaintexts.    |
| **`lvthn-cli`**  | [▼](https://www.npmjs.com/package/lvthn)   | [🛈](https://github.com/xero/leviathan-demos/tree/main/lvthn-cli)  | [¶](https://github.com/xero/leviathan-demos/blob/main/lvthn-cli/README.md)  | File encryption CLI tool supporting both Serpent-256 and XChaCha20-Poly1305 via the `--cipher` flag. Keyfiles are compatible with both ciphers; the header byte determines decryption automatically.    |
