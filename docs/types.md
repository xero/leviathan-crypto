<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### TypeScript Interfaces

Defines the abstract interfaces all leviathan-crypto cryptographic classes implement. These are type-only exports; they contain no runtime code and generate no JavaScript output.

> ### Table of Contents
> - [API Reference](#api-reference)
> - [Usage Examples](#usage-examples)
> - [Generator](#generator)
> - [HashFn](#hashfn)
> - [WasmSource](#wasmsource)
> - [CipherSuite](#ciphersuite)
> - [DerivedKeys](#derivedkeys)
> - [SealStreamOpts](#sealstreamopts)
> - [PoolOpts](#poolopts)

---

## API Reference

Use these interfaces when you need generic code that works with any hash function, any cipher, or any AEAD scheme without depending on a specific implementation. They are available immediately on import with no `init()` call required.

### Hash

```typescript
interface Hash {
  hash(msg: Uint8Array): Uint8Array;
  dispose(): void;
}
```

Interface for unkeyed hash functions (e.g., SHA-256, SHA-512, SHA-3).

| Method | Description |
|---|---|
| `hash(msg)` | Hashes the entire message and returns the digest as a new `Uint8Array`. |
| `dispose()` | Releases WASM resources and wipes internal buffers. Call when done. |

---

### KeyedHash

```typescript
interface KeyedHash {
  hash(key: Uint8Array, msg: Uint8Array): Uint8Array;
  dispose(): void;
}
```

Interface for keyed hash functions / MACs (e.g., HMAC-SHA256, HMAC-SHA512).

`KeyedHash` does **not** extend `Hash`. Its `hash` method takes a `key` parameter in addition to the message.

| Method | Description |
|---|---|
| `hash(key, msg)` | Computes the keyed hash / MAC over `msg` using `key`. Returns the tag as a new `Uint8Array`. |
| `dispose()` | Releases WASM resources and wipes internal buffers. Call when done. |

---

### Blockcipher

```typescript
interface Blockcipher {
  encrypt(block: Uint8Array): Uint8Array;
  decrypt(block: Uint8Array): Uint8Array;
  dispose(): void;
}
```

Interface for raw block ciphers (e.g., Serpent in ECB mode). Operates on single blocks.

| Method | Description |
|---|---|
| `encrypt(block)` | Encrypts a single block and returns the ciphertext. |
| `decrypt(block)` | Decrypts a single block and returns the plaintext. |
| `dispose()` | Releases WASM resources and wipes internal buffers (including expanded key schedule). |

---

### Streamcipher

```typescript
interface Streamcipher {
  encrypt(msg: Uint8Array): Uint8Array;
  decrypt(msg: Uint8Array): Uint8Array;
  dispose(): void;
}
```

Interface for stream ciphers and block cipher streaming modes (e.g., Serpent-CTR, ChaCha20). Handles arbitrary-length messages.

| Method | Description |
|---|---|
| `encrypt(msg)` | Encrypts an arbitrary-length message. Returns the ciphertext (same length as input). |
| `decrypt(msg)` | Decrypts an arbitrary-length ciphertext. Returns the plaintext (same length as input). |
| `dispose()` | Releases WASM resources and wipes internal buffers. |

---

### AEAD

```typescript
interface AEAD {
  encrypt(msg: Uint8Array, aad?: Uint8Array): Uint8Array;
  decrypt(ciphertext: Uint8Array, aad?: Uint8Array): Uint8Array;
  dispose(): void;
}
```

Interface for authenticated encryption with associated data (e.g., XChaCha20-Poly1305). Provides both confidentiality and integrity.

| Method | Description |
|---|---|
| `encrypt(msg, aad?)` | Encrypts `msg` and authenticates both `msg` and optional `aad`. Returns ciphertext with appended authentication tag. |
| `decrypt(ciphertext, aad?)` | Decrypts and verifies the authentication tag. Returns plaintext on success. Throws `Error` on authentication failure. Never returns null. |
| `dispose()` | Releases WASM resources and wipes internal buffers. |

---

## Usage Examples

### Type-constraining a function parameter

```typescript
import type { Hash } from 'leviathan-crypto'

function digestAndLog(hasher: Hash, data: Uint8Array): Uint8Array {
  const digest = hasher.hash(data)
  console.log('digest length:', digest.length)
  return digest
}
```

This function accepts any `Hash` implementation (`SHA256`, `SHA512`, `SHA3_256`, etc.) without importing any of them directly.

---

### Accepting any AEAD scheme

```typescript
import type { AEAD } from 'leviathan-crypto'

function sealMessage(aead: AEAD, plaintext: Uint8Array, metadata: Uint8Array): Uint8Array {
  return aead.encrypt(plaintext, metadata)
}

function openMessage(aead: AEAD, ciphertext: Uint8Array, metadata: Uint8Array): Uint8Array {
  // decrypt() throws on auth failure, no null check needed
  return aead.decrypt(ciphertext, metadata)
}
```

---

### Generic keyed-hash wrapper

```typescript
import type { KeyedHash } from 'leviathan-crypto'

function authenticate(mac: KeyedHash, key: Uint8Array, ...parts: Uint8Array[]): Uint8Array {
  // Concatenate all message parts, then compute the tag
  const total = parts.reduce((sum, p) => sum + p.length, 0)
  const msg = new Uint8Array(total)
  let offset = 0
  for (const part of parts) {
    msg.set(part, offset)
    offset += part.length
  }
  return mac.hash(key, msg)
}
```

---

### Storing a cipher with its interface type

```typescript
import type { Streamcipher, Blockcipher } from 'leviathan-crypto'

interface EncryptionContext {
  cipher: Streamcipher | Blockcipher
  mode: 'stream' | 'block'
}

function cleanup(ctx: EncryptionContext): void {
  ctx.cipher.dispose()
}
```

---

## Generator

```typescript
interface Generator {
  readonly keySize: number;       // bytes
  readonly blockSize: number;     // bytes per cipher block
  readonly counterSize: number;   // bytes
  readonly wasmModules: readonly string[];
  generate(key: Uint8Array, counter: Uint8Array, n: number): Uint8Array;
}
```

Stateless cipher PRF. Used by `Fortuna` as the generator slot.
Implementations are plain const objects; they assert that no stateful
instance owns the underlying WASM module before each call but do not
acquire it themselves.

| Member | Description |
|---|---|
| `keySize` | Generator key size in bytes. Must equal the paired `HashFn.outputSize` when used with `Fortuna`. |
| `blockSize` | Bytes per cipher block. Used by `Fortuna` to compute counter advancement. |
| `counterSize` | Counter width in bytes. `Fortuna` allocates its `genCnt` of this size. |
| `wasmModules` | List of WASM module names the generator depends on. Used for `init()` preflight in `Fortuna.create()`. |
| `generate(key, counter, n)` | Produces `n` bytes of keystream from `(key, counter)`. Stateless; does not mutate either input. |

Shipped implementations: `SerpentGenerator` (from `'leviathan-crypto/serpent'`), `ChaCha20Generator` (from `'leviathan-crypto/chacha20'`).

---

## HashFn

```typescript
interface HashFn {
  readonly outputSize: number;    // bytes
  readonly wasmModules: readonly string[];
  digest(msg: Uint8Array): Uint8Array;
}
```

Stateless hash function. Used by `Fortuna` for the accumulator chain and
the reseed key derivation. Distinct from the existing `Hash` interface
above, which describes class-shaped instances that own scratch state and
require `dispose()`.

| Member | Description |
|---|---|
| `outputSize` | Digest size in bytes. Must equal the paired `Generator.keySize` when used with `Fortuna`. |
| `wasmModules` | List of WASM module names the hash depends on. |
| `digest(msg)` | Produces a digest of the input. Stateless; safe to call concurrently with itself within a single JavaScript turn. |

Shipped implementations: `SHA256Hash` (from `'leviathan-crypto/sha2'`), `SHA3_256Hash` (from `'leviathan-crypto/sha3'`).

---

## WasmSource

Union type for WASM module sources. Accepted by `init()`, `serpentInit()`, etc.

`string | URL | ArrayBuffer | Uint8Array | WebAssembly.Module | Response | Promise<Response>`

---

## CipherSuite

Cipher-specific logic injected into `SealStream` and `OpenStream`.

| Field | Type | Description |
|-------|------|-------------|
| `formatEnum` | `number` | Wire format ID encoded in header byte 0 bits 0-5 (max 0x3f): bits 0-3 = cipher nibble (0x1=xchacha20, 0x2=serpent), bits 4-5 = KEM selector (0x00=none, 0x10=ML-KEM-512, 0x20=ML-KEM-768, 0x30=ML-KEM-1024), bit 6 reserved |
| `formatName` | `string` | Human-readable label, e.g. `'xchacha20'`, `'serpent'`, `'mlkem768+xchacha20'` |
| `hkdfInfo` | `string` | HKDF info string for key derivation |
| `keySize` | `number` | Seal/encrypt key size in bytes (encapsulation key bytes for KEM suites) |
| `decKeySize` | `number \| undefined` | Open/decrypt key size in bytes (decapsulation key bytes for KEM suites). Absent → same as `keySize` (symmetric case) |
| `kemCtSize` | `number` | KEM ciphertext byte length appended to the header in the preamble. `0` for symmetric suites |
| `tagSize` | `number` | Authentication tag size in bytes |
| `padded` | `boolean` | Whether ciphertext includes padding (PKCS7 for CBC) |
| `wasmChunkSize` | `number` | WASM buffer capacity for one padded chunk. `SealStreamPool.create()` validates `paddedFull ≤ wasmChunkSize` at startup for padded ciphers and throws `RangeError` if the check fails. `SerpentCipher`: 65552. `XChaCha20Cipher`: 65536. `KyberSuite` forwards from its inner cipher. |
| `wasmModules` | `readonly string[]` | Cipher-specific WASM modules used by pool workers and per-chunk operations (not transitive dependencies such as HKDF-SHA-256 used by `deriveKeys()`) |

| Method | Signature | Description |
|--------|-----------|-------------|
| `deriveKeys` | `(masterKey, nonce, kemCt?) → DerivedKeys` | HKDF key derivation. `kemCt` is the KEM ciphertext; present only for hybrid suites. |
| `sealChunk` | `(keys, counterNonce, chunk, aad?) → Uint8Array` | Encrypt one chunk |
| `openChunk` | `(keys, counterNonce, chunk, aad?) → Uint8Array` | Decrypt one chunk |
| `wipeKeys` | `(keys) → void` | Zero derived key material |
| `createPoolWorker` | `() → Worker` | Create a Web Worker for pool use. Default spawns a classic worker from a blob URL over a build-time IIFE; override via spread for strict-CSP environments. See [ciphersuite.md](./ciphersuite.md). |

Implementations: `XChaCha20Cipher`, `SerpentCipher` (plain `const` objects, not classes), and `KyberSuite` (factory function returning a `CipherSuite`). See [ciphersuite.md](./ciphersuite.md).

> [!IMPORTANT]
> All CipherSuite implementations use HKDF-SHA-256 in `deriveKeys()`. The stream layer requires
> `sha2` to be initialized regardless of which cipher is selected.

---

## DerivedKeys

Opaque key material returned by `CipherSuite.deriveKeys()`.

| Field | Type | Description |
|-------|------|-------------|
| `bytes` | `readonly Uint8Array` | Raw derived key bytes (opaque to the stream layer) |
| `kemCiphertext?` | `readonly Uint8Array \| undefined` | KEM ciphertext produced during encapsulation. Present only for hybrid KEM suites; absent for symmetric suites. |

---

## SealStreamOpts

Options for `SealStream` constructor.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `chunkSize` | `number` | `65536` | Chunk size in bytes. Range: [1024, 16777215]. |
| `framed` | `boolean` | `false` | Enable u32be length-prefixed framing. |

---

## PoolOpts

Options for `SealStreamPool.create()`.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `wasm` | `WasmSource \| Record<string, WasmSource>` | | WASM module source(s). Single source for single-module ciphers, Record for multi-module. |
| `workers` | `number` | `navigator.hardwareConcurrency ?? 4` | Number of Web Workers. |
| `chunkSize` | `number` | `65536` | Chunk size in bytes. |
| `framed` | `boolean` | `false` | Enable framed mode. |
| `jobTimeout` | `number` | `30000` | Per-job timeout in milliseconds. |

---

## Ratchet types

Shared types for the ratchet KDF module. See [ratchet.md](./ratchet.md) for full API.

### MlKemLike

Structural interface satisfied by `MlKem512`, `MlKem768`, and `MlKem1024`. Used as the `kem` parameter type for `kemRatchetEncap`, `kemRatchetDecap`, and `RatchetKeypair`.

```typescript
interface MlKemLike {
  readonly params: KyberParams
  keygen(): { encapsulationKey: Uint8Array; decapsulationKey: Uint8Array }
  encapsulate(ek: Uint8Array): { ciphertext: Uint8Array; sharedSecret: Uint8Array }
  decapsulate(dk: Uint8Array, ct: Uint8Array): Uint8Array
}
```

### RatchetInitResult

```typescript
interface RatchetInitResult {
  readonly nextRootKey:  Uint8Array  // 32 bytes
  readonly sendChainKey: Uint8Array  // 32 bytes
  readonly recvChainKey: Uint8Array  // 32 bytes
}
```

### KemEncapResult

```typescript
interface KemEncapResult {
  readonly nextRootKey:  Uint8Array  // 32 bytes
  readonly sendChainKey: Uint8Array  // 32 bytes
  readonly recvChainKey: Uint8Array  // 32 bytes
  readonly kemCt:        Uint8Array  // ML-KEM ciphertext — transmit in-band
}
```

### KemDecapResult

```typescript
interface KemDecapResult {
  readonly nextRootKey:  Uint8Array  // 32 bytes
  readonly sendChainKey: Uint8Array  // 32 bytes
  readonly recvChainKey: Uint8Array  // 32 bytes
}
```

### RatchetMessageHeader

```typescript
interface RatchetMessageHeader {
  readonly epoch:   number        // sender's epoch at seal time; starts 0, increments on ratchet step
  readonly counter: number        // KDFChain.n at seal time (post-step value, first message = 1)
  readonly pn?:     number        // previous chain length — present only on the first message of a new epoch
  readonly kemCt?:  Uint8Array    // ML-KEM ciphertext — present only on the first message of a new epoch (encap side)
}
```

Canonical header shape for a ratchet-protected message. `pn` and `kemCt` are absent on every message except the first one of a new epoch, where both must be present together.

### ResolveHandle

Return type of `SkippedKeyStore.resolve()`.

```typescript
interface ResolveHandle {
  readonly key: Uint8Array  // 32-byte message key — throws after settlement
  commit():   void          // wipe key and mark settled — call on successful decrypt
  rollback(): void          // return key to store and mark settled — call on auth failure
}
```

`commit()` and `rollback()` are mutually exclusive; calling either a second time (or calling the other after settling) throws `Error: 'SkippedKeyStore: handle already settled'`. Accessing `.key` after settlement also throws. This enforces the delete-on-use contract: a key is consumed exactly once, either by committing (decrypt succeeded, key wiped) or rolling back (decrypt failed, key returned to the store for a future legitimate delivery at the same counter).

---


## Cross-References

| Document | Description |
| -------- | ----------- |
| [index](./README.md) | Project Documentation index |
| [architecture](./architecture.md) | architecture overview, module relationships, buffer layouts, and build pipeline |
| [utils](./utils.md) | encoding utilities and `constantTimeEqual` for verifying MACs from `KeyedHash` |
| [serpent](./serpent.md) | Serpent classes implement `Blockcipher`, `Streamcipher`, and `AEAD` |
| [chacha20](./chacha20.md) | `XChaCha20Cipher` is a `CipherSuite` for `SealStream`/`OpenStream`/`Seal`; `Seal` provides one-shot AEAD over any `CipherSuite`; `ChaCha20`/`ChaCha20Poly1305`/`XChaCha20Poly1305` are stateless primitives |
| [sha2](./sha2.md) | SHA-2 classes implement `Hash`; HMAC classes implement `KeyedHash` |
| [sha3](./sha3.md) | SHA-3 classes implement `Hash`; SHAKE classes extend with XOF API |
| [ratchet](./ratchet.md) | ratchet KDF primitives; `MlKemLike`, `RatchetInitResult`, `KemEncapResult`, `KemDecapResult`, `RatchetMessageHeader`, `ResolveHandle` |
| [test-suite](./test-suite.md) | test suite structure and vector corpus |

