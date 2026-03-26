# Leviathan Crypto Library Documentation

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

## Installation

```bash
bun i leviathan-crypto
# or npm slow mode
npm install leviathan-crypto
```

## Quick Start

### Authenticated encryption with Serpent (recommended)

```typescript
import { init, SerpentSeal, randomBytes } from 'leviathan-crypto'

await init(['serpent', 'sha2'])

const key = randomBytes(64)  // 64-byte key (encKey + macKey)

const seal = new SerpentSeal()
const ciphertext = seal.encrypt(key, plaintext)  // Serpent-CBC + HMAC-SHA256
const decrypted  = seal.decrypt(key, ciphertext) // throws on tamper

seal.dispose()
```

### Incremental streaming AEAD

```typescript
import { init, SerpentStreamSealer, SerpentStreamOpener, randomBytes } from 'leviathan-crypto'

await init(['serpent', 'sha2'])

const key = randomBytes(64)

// Seal side
const sealer = new SerpentStreamSealer(key, 65536)
const header = sealer.header()       // transmit to opener before any chunks

const chunk0 = sealer.seal(data0)    // exactly chunkSize bytes
const chunk1 = sealer.seal(data1)
const last   = sealer.final(tail)    // any size up to chunkSize; wipes key on return

// Open side
const opener = new SerpentStreamOpener(key, header)

const pt0 = opener.open(chunk0)
const pt1 = opener.open(chunk1)
const ptN = opener.open(last)        // detects final chunk; wipes key on return

// Reordering, truncation, and cross-stream splicing all throw on open()
```

---

## Getting Started

- [architecture.md](./architecture.md): Architecture overview, build pipeline, and module relationships
- [init.md](./init.md): `init()` API and WASM loading modes
- [wasm.md](./wasm.md): Primer on Web Assembly in this project's context

---

## API Reference

### Serpent-256

| Module | Description |
|--------|-------------|
| [serpent.md](./serpent.md) | TypeScript API -- `SerpentSeal`, `SerpentStream`, `SerpentStreamPool`, `SerpentStreamSealer`, `SerpentStreamOpener`, `Serpent`, `SerpentCtr`, `SerpentCbc` |
| [asm_serpent.md](./asm_serpent.md) | WASM implementation -- bitslice S-boxes, key schedule, CTR/CBC modes |

### ChaCha20 / Poly1305

| Module | Description |
|--------|-------------|
| [chacha20.md](./chacha20.md) | TypeScript API -- `ChaCha20`, `Poly1305`, `ChaCha20Poly1305`, `XChaCha20Poly1305` |
| [asm_chacha.md](./asm_chacha.md) | WASM implementation -- quarter-round, Poly1305 accumulator, HChaCha20 |

### SHA-2

| Module | Description |
|--------|-------------|
| [sha2.md](./sha2.md) | TypeScript API -- `SHA256`, `SHA512`, `SHA384`, `HMAC_SHA256`, `HMAC_SHA512`, `HMAC_SHA384`, `HKDF_SHA256`, `HKDF_SHA512` |
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
| [architecture.md](./architecture.md) | Repository structure, architecture diagram, build pipeline, module relationships, buffer layouts, correctness contract, limitations |
| [test-suite.md](./test-suite.md) | Test suite structure, vector corpus, gate discipline |
| [serpent_reference.md](./serpent_reference.md) | Serpent algorithm overview: S-boxes, linear transform, round structure, known attacks |
| [wasm.md](./wasm.md) | Primer on Web Assembly in this project's context |
| [argon2id.md](./argon2id.md) | Key derivation and password hashing examples using the argon2id library with Leviathan |
| [branding.md](./branding.md) | Project artwork and other PR materials |

## Algorithm correctness and verifications

| Primitive | Audit Description |
| --- | ---- |
| [serpent_audit.md](./serpent_audit.md) | Serpent256 Correctness verification, side-channel analysis, cryptanalytic paper review |
| [chacha_audit.md](./chacha_audit.md) | XChaCha20-Poly1305 correctness, Poly1305 field arithmetic, HChaCha20 nonce extension |
| [sha2_audit.md](./sha2_audit.md) | SHA-256/512/384 correctness, HMAC and HKDF composition, constant verification |
| [sha3_audit.md](./sha3_audit.md) | Keccak permutation correctness, θ/ρ/π/χ/ι step verification, round constant derivation |
| [hmac_audit.md](./hmac_audit.md) | HMAC-SHA256/512/384 construction, key processing, RFC 4231 vector coverage |
| [hkdf_audit.md](./hkdf_audit.md) | HKDF extract-then-expand, info field domain separation, SerpentStream key derivation |

## Security Philosophy

Serpent was chosen as the flagship cipher for its conservative 32-round design with a 20-round security margin, the widest of any AES finalist. All S-box operations use a bitslice implementation that eliminates cache-timing side channels. WASM execution runs outside the JavaScript JIT, providing practical constant-time guarantees for cryptographic operations. All security-sensitive comparisons (MAC verification, padding validation) use XOR-accumulate patterns with no early return on mismatch. The library enforces an explicit `init()` gate: no class silently auto-initializes, so there are no hidden initialization costs or race conditions. Every class exposes a `dispose()` method that calls `wipeBuffers()` to zero key material and intermediate state from WASM linear memory.

---

## Two-Tier Initialization

leviathan-crypto supports two import patterns with different bundle-size trade-offs:

### Root import (all modules)

```typescript
import { init, SerpentSeal, SHA256 } from 'leviathan-crypto'

await init(['serpent', 'sha2'])
```

The root `init()` dispatches to each module's internal init function and loads the
requested modules in parallel via `Promise.all`. This is the simplest approach
but means all four embedded WASM binaries are reachable from the root barrel's
dependency graph.

### Subpath import (tree-shakeable)

```typescript
import { serpentInit, SerpentSeal } from 'leviathan-crypto/serpent'

await serpentInit()
```

Each subpath export has its own init function (e.g. `serpentInit(mode?, opts?)`)
that loads only that module's WASM binary. A bundler with tree-shaking support (and
`"sideEffects": false` in `package.json`) will exclude the other three
modules' embedded binaries from the bundle entirely.

### Subpath exports

| Subpath | Entry point |
|---------|-------------|
| `leviathan-crypto` | `./dist/index.js` |
| `leviathan-crypto/serpent` | `./dist/serpent/index.js` |
| `leviathan-crypto/chacha20` | `./dist/chacha20/index.js` |
| `leviathan-crypto/sha2` | `./dist/sha2/index.js` |
| `leviathan-crypto/sha3` | `./dist/sha3/index.js` |
| `leviathan-crypto/chacha20/pool` | `./dist/chacha20/pool.js` |

> [!NOTE]
> `pool.worker.js` ships in the package under `dist/chacha20/` and is loaded
> by the pool at runtime, but it is not a named subpath export in the `exports` map.
> Do not import it directly: the pool constructor resolves it automatically.

## All Exports

### Initialization (root barrel `index.ts`)

| Export | Kind | Description |
|--------|------|-------------|
| `init` | function | Load and cache WASM modules. Dispatches to per-module init functions. |
| `Module` | type | `'serpent' \| 'chacha20' \| 'sha2' \| 'sha3'` |
| `Mode` | type | `'embedded' \| 'streaming' \| 'manual'` |
| `InitOpts` | type | Options for `init()`: `wasmUrl`, `wasmBinary` |

### Serpent (`serpent/index.ts`) -- requires `init(['serpent', 'sha2'])` for authenticated classes, `init(['serpent'])` for raw modes

| Export | Kind | Description |
|--------|------|-------------|
| `serpentInit` | function | Module-scoped init. `serpentInit(mode?, opts?)` loads only serpent. |
| `SerpentSeal` | class | Authenticated encryption: Serpent-CBC + HMAC-SHA256. `encrypt(key, plaintext)`, `decrypt(key, ciphertext)`. 64-byte key. |
| `SerpentStream` | class | Chunked one-shot AEAD for large payloads. `seal(key, plaintext, chunkSize?)`, `open(key, ciphertext)`. 32-byte key. |
| `SerpentStreamPool` | class | Worker-pool wrapper for `SerpentStream`. Parallelises chunk encryption across isolated WASM instances. `SerpentStreamPool.create(opts?)` static factory. |
| `SerpentStreamSealer` | class | Incremental streaming AEAD: seal one chunk at a time. `header()`, `seal(plaintext)`, `final(plaintext)`, `dispose()`. 64-byte key. |
| `SerpentStreamOpener` | class | Incremental streaming AEAD: open one chunk at a time. `open(chunk)`, `dispose()`. Initialized from sealer `header()` output. |
| `Serpent` | class | Serpent-256 ECB block cipher. `loadKey()`, `encryptBlock()`, `decryptBlock()`. Unauthenticated. |
| `SerpentCtr` | class | Serpent-256 CTR mode. `beginEncrypt()`, `encryptChunk()`, `beginDecrypt()`, `decryptChunk()`. Unauthenticated. |
| `SerpentCbc` | class | Serpent-256 CBC mode with PKCS7 padding. `encrypt(key, iv, plaintext)`, `decrypt(key, iv, ciphertext)`. Unauthenticated. |
| `StreamPoolOpts` | type | Options for `SerpentStreamPool.create()`: worker count. |

### ChaCha20 (`chacha20/index.ts`) -- requires `init(['chacha20'])` or subpath `chacha20Init()`

| Export | Kind | Description |
|--------|------|-------------|
| `chacha20Init` | function | Module-scoped init. `chacha20Init(mode?, opts?)` loads only chacha20. |
| `ChaCha20` | class | ChaCha20 stream cipher (RFC 8439). `beginEncrypt()`, `encryptChunk()`. |
| `Poly1305` | class | Poly1305 one-time MAC (RFC 8439). `mac(key, msg)`. |
| `ChaCha20Poly1305` | class | ChaCha20-Poly1305 AEAD (RFC 8439). `encrypt(key, nonce, plaintext, aad?)`, `decrypt(key, nonce, ciphertext, aad?)`. |
| `XChaCha20Poly1305` | class | XChaCha20-Poly1305 AEAD. 24-byte nonce. `encrypt(key, nonce, plaintext, aad?)`, `decrypt(key, nonce, ciphertext, aad?)`. |
| `XChaCha20Poly1305Pool` | class | Worker-pool wrapper for `XChaCha20Poly1305`. `XChaCha20Poly1305Pool.create(opts?)` static factory. |
| `PoolOpts` | type | Options for `XChaCha20Poly1305Pool.create()`: worker count, worker script URL. |

### SHA-2 (`sha2/index.ts`) -- requires `init(['sha2'])` or subpath `sha2Init()`

| Export | Kind | Description |
|--------|------|-------------|
| `sha2Init` | function | Module-scoped init. `sha2Init(mode?, opts?)` loads only sha2. |
| `SHA256` | class | SHA-256 hash (FIPS 180-4). `hash(msg)` returns 32 bytes. |
| `SHA384` | class | SHA-384 hash (FIPS 180-4). `hash(msg)` returns 48 bytes. |
| `SHA512` | class | SHA-512 hash (FIPS 180-4). `hash(msg)` returns 64 bytes. |
| `HMAC_SHA256` | class | HMAC-SHA256 (RFC 2104). `hash(key, msg)` returns 32 bytes. |
| `HMAC_SHA384` | class | HMAC-SHA384 (RFC 2104). `hash(key, msg)` returns 48 bytes. |
| `HMAC_SHA512` | class | HMAC-SHA512 (RFC 2104). `hash(key, msg)` returns 64 bytes. |
| `HKDF_SHA256` | class | HKDF with HMAC-SHA256 (RFC 5869). `derive(ikm, salt, info, length)`. |
| `HKDF_SHA512` | class | HKDF with HMAC-SHA512 (RFC 5869). `derive(ikm, salt, info, length)`. |

### SHA-3 (`sha3/index.ts`) -- requires `init(['sha3'])` or subpath `sha3Init()`

| Export | Kind | Description |
|--------|------|-------------|
| `sha3Init` | function | Module-scoped init. `sha3Init(mode?, opts?)` loads only sha3. |
| `SHA3_224` | class | SHA3-224 hash (FIPS 202). `hash(msg)` returns 28 bytes. |
| `SHA3_256` | class | SHA3-256 hash (FIPS 202). `hash(msg)` returns 32 bytes. |
| `SHA3_384` | class | SHA3-384 hash (FIPS 202). `hash(msg)` returns 48 bytes. |
| `SHA3_512` | class | SHA3-512 hash (FIPS 202). `hash(msg)` returns 64 bytes. |
| `SHAKE128` | class | SHAKE128 XOF (FIPS 202). Unbounded output. `hash(msg, outputLength)`, `absorb(msg)`, `squeeze(n)`, `reset()`. |
| `SHAKE256` | class | SHAKE256 XOF (FIPS 202). Unbounded output. `hash(msg, outputLength)`, `absorb(msg)`, `squeeze(n)`, `reset()`. |

### Fortuna (`fortuna.ts`) -- requires `init(['serpent', 'sha2'])`

| Export | Kind | Description |
|--------|------|-------------|
| `Fortuna` | class | Fortuna CSPRNG (Ferguson & Schneier). `Fortuna.create()` static factory, `get(n)`, `addEntropy()`, `stop()`. |

### Types (`types.ts`)

| Export | Kind | Description |
|--------|------|-------------|
| `Hash` | interface | `hash(msg): Uint8Array`, `dispose()` |
| `KeyedHash` | interface | `hash(key, msg): Uint8Array`, `dispose()` |
| `Blockcipher` | interface | `encrypt(block): Uint8Array`, `decrypt(block): Uint8Array`, `dispose()` |
| `Streamcipher` | interface | `encrypt(msg): Uint8Array`, `decrypt(msg): Uint8Array`, `dispose()` |
| `AEAD` | interface | `encrypt(msg, aad?): Uint8Array`, `decrypt(ciphertext, aad?): Uint8Array`, `dispose()` |

### Utilities (`utils.ts`)

| Export | Kind | Description |
|--------|------|-------------|
| `hexToBytes` | function | Hex string to `Uint8Array`. Accepts `0x` prefix, uppercase/lowercase. |
| `bytesToHex` | function | `Uint8Array` to lowercase hex string. |
| `utf8ToBytes` | function | UTF-8 string to `Uint8Array`. |
| `bytesToUtf8` | function | `Uint8Array` to UTF-8 string. |
| `base64ToBytes` | function | Base64/base64url string to `Uint8Array`. Returns `undefined` on invalid input. |
| `bytesToBase64` | function | `Uint8Array` to base64 string. Pass `url=true` for base64url. |
| `constantTimeEqual` | function | Constant-time byte-array equality (XOR-accumulate, no early return). |
| `wipe` | function | Zero a typed array in place. |
| `xor` | function | XOR two equal-length `Uint8Array`s, returns new array. |
| `concat` | function | Concatenate two `Uint8Array`s, returns new array. |
| `randomBytes` | function | Cryptographically secure random bytes via Web Crypto API. |

