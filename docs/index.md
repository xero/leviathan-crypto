# leviathan-crypto

leviathan-crypto is a strictly-typed, audited WebAssembly cryptography library for the web. All cryptographic computation runs in WASM (AssemblyScript), outside the JavaScript JIT, providing deterministic execution and practical constant-time guarantees. The TypeScript layer provides the public API -- input validation, type safety, and developer ergonomics.

## Installation

```bash
npm install leviathan-crypto
```

## Quick Start

```typescript
import { init, SerpentCbc, randomBytes, bytesToHex } from 'leviathan-crypto'

await init(['serpent'])

const key = randomBytes(32)  // 256-bit key
const iv = randomBytes(16)   // 128-bit IV

const cipher = new SerpentCbc()
const plaintext = new TextEncoder().encode('Hello, leviathan-crypto!')
const ciphertext = cipher.encrypt(key, iv, plaintext)
const decrypted = cipher.decrypt(key, iv, ciphertext)

console.log(bytesToHex(ciphertext))            // encrypted output
console.log(new TextDecoder().decode(decrypted)) // 'Hello, leviathan-crypto!'

cipher.dispose() // wipe key material from WASM memory
```

## Module Reference

| Category | Module | Description |
|----------|--------|-------------|
| Initialization | [init](./init.md) | WASM module loading and initialization |
| Symmetric Cipher | [serpent](./serpent.md) | Serpent-256 block cipher (ECB, CTR, CBC) |
| Stream Cipher / AEAD | [chacha20](./chacha20.md) | ChaCha20, Poly1305, ChaCha20-Poly1305, XChaCha20-Poly1305 |
| Hash Functions | [sha2](./sha2.md) | SHA-256, SHA-384, SHA-512 |
| Hash Functions | [sha3](./sha3.md) | SHA3-224/256/384/512, SHAKE128, SHAKE256 |
| MAC | [sha2](./sha2.md) | HMAC-SHA256, HMAC-SHA384, HMAC-SHA512 |
| CSPRNG | [fortuna](./fortuna.md) | Fortuna CSPRNG (Serpent + SHA-256) |
| Utilities | [utils](./utils.md) | Encoding, comparison, random bytes |
| Types | [types](./types.md) | TypeScript interfaces |
| Internal | [loader](./loader.md) | WASM binary loading |

## Security Philosophy

Serpent was chosen as the flagship cipher for its conservative 32-round design with a 20-round security margin -- the widest of any AES finalist. All S-box operations use a bitslice implementation that eliminates cache-timing side channels. WASM execution runs outside the JavaScript JIT, providing practical constant-time guarantees for cryptographic operations. All security-sensitive comparisons (MAC verification, padding validation) use XOR-accumulate patterns with no early return on mismatch. The library enforces an explicit `init()` gate -- no class silently auto-initializes, so there are no hidden initialization costs or race conditions. Every class exposes a `dispose()` method that calls `wipeBuffers()` to zero key material and intermediate state from WASM linear memory.

## Two-Tier Initialization

leviathan-crypto supports two import patterns with different bundle-size trade-offs:

### Root import (all modules)

```typescript
import { init, Serpent, SHA256 } from 'leviathan-crypto'

await init(['serpent', 'sha2'])
```

The root `init()` dispatches to each module's internal `init()` and loads the
requested modules in parallel via `Promise.all`. This is the simplest approach
but means all four embedded WASM binaries are reachable from the root barrel's
dependency graph.

### Subpath import (tree-shakeable)

```typescript
import { init, Serpent } from 'leviathan-crypto/serpent'

await init()
```

Each subpath export has its own `init(mode?, opts?)` that loads only that
module's WASM binary. A bundler with tree-shaking support (and
`"sideEffects": false` in `package.json`) will exclude the other three
modules' embedded binaries from the bundle entirely.

---

## All Exports

### Initialization (root barrel `index.ts`)

| Export | Kind | Description |
|--------|------|-------------|
| `init` | function | Load and cache WASM modules. Dispatches to per-module `init()` functions. |
| `Module` | type | `'serpent' \| 'chacha20' \| 'sha2' \| 'sha3'` |
| `Mode` | type | `'embedded' \| 'streaming' \| 'manual'` |
| `InitOpts` | type | Options for `init()`: `wasmUrl`, `wasmBinary` |

### Serpent (`serpent/index.ts`) -- requires `init(['serpent'])` or subpath `init()`

| Export | Kind | Description |
|--------|------|-------------|
| `init` | function | Module-scoped init. `init(mode?, opts?)` loads only serpent. |
| `Serpent` | class | Serpent-256 ECB block cipher. `loadKey()`, `encryptBlock()`, `decryptBlock()`. |
| `SerpentCtr` | class | Serpent-256 CTR mode. `beginEncrypt()`, `encryptChunk()`, `beginDecrypt()`, `decryptChunk()`. Unauthenticated. |
| `SerpentCbc` | class | Serpent-256 CBC mode with PKCS7 padding. `encrypt(key, iv, plaintext)`, `decrypt(key, iv, ciphertext)`. Unauthenticated. |

### ChaCha20 (`chacha20/index.ts`) -- requires `init(['chacha20'])` or subpath `init()`

| Export | Kind | Description |
|--------|------|-------------|
| `init` | function | Module-scoped init. `init(mode?, opts?)` loads only chacha20. |
| `ChaCha20` | class | ChaCha20 stream cipher (RFC 8439). `beginEncrypt()`, `encryptChunk()`. |
| `Poly1305` | class | Poly1305 one-time MAC (RFC 8439). `mac(key, msg)`. |
| `ChaCha20Poly1305` | class | ChaCha20-Poly1305 AEAD (RFC 8439). `encrypt(key, nonce, plaintext, aad)`, `decrypt(key, nonce, ciphertext, tag, aad)`. |
| `XChaCha20Poly1305` | class | XChaCha20-Poly1305 AEAD (draft-irtf-cfrg-xchacha). 24-byte nonce. `encrypt(key, nonce, plaintext, aad)`, `decrypt(key, nonce, ciphertext, aad)`. |

### SHA-2 (`sha2/index.ts`) -- requires `init(['sha2'])` or subpath `init()`

| Export | Kind | Description |
|--------|------|-------------|
| `init` | function | Module-scoped init. `init(mode?, opts?)` loads only sha2. |
| `SHA256` | class | SHA-256 hash (FIPS 180-4). `hash(msg)` returns 32 bytes. |
| `SHA384` | class | SHA-384 hash (FIPS 180-4). `hash(msg)` returns 48 bytes. |
| `SHA512` | class | SHA-512 hash (FIPS 180-4). `hash(msg)` returns 64 bytes. |
| `HMAC_SHA256` | class | HMAC-SHA256 (RFC 2104). `hash(key, msg)` returns 32 bytes. |
| `HMAC_SHA384` | class | HMAC-SHA384 (RFC 2104). `hash(key, msg)` returns 48 bytes. |
| `HMAC_SHA512` | class | HMAC-SHA512 (RFC 2104). `hash(key, msg)` returns 64 bytes. |

### SHA-3 (`sha3/index.ts`) -- requires `init(['sha3'])` or subpath `init()`

| Export | Kind | Description |
|--------|------|-------------|
| `init` | function | Module-scoped init. `init(mode?, opts?)` loads only sha3. |
| `SHA3_224` | class | SHA3-224 hash (FIPS 202). `hash(msg)` returns 28 bytes. |
| `SHA3_256` | class | SHA3-256 hash (FIPS 202). `hash(msg)` returns 32 bytes. |
| `SHA3_384` | class | SHA3-384 hash (FIPS 202). `hash(msg)` returns 48 bytes. |
| `SHA3_512` | class | SHA3-512 hash (FIPS 202). `hash(msg)` returns 64 bytes. |
| `SHAKE128` | class | SHAKE128 XOF (FIPS 202). `hash(msg, outputLength)` returns 1--168 bytes. |
| `SHAKE256` | class | SHAKE256 XOF (FIPS 202). `hash(msg, outputLength)` returns 1--136 bytes. |

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
| `AEAD` | interface | `encrypt(msg, aad?): Uint8Array`, `decrypt(ciphertext, aad?): Uint8Array \| null`, `dispose()` |

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
