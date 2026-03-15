# Public TypeScript interfaces for cryptographic primitives

## Overview

This module defines the abstract interfaces that all leviathan-crypto cryptographic classes implement. These are **type-only exports** -- they contain no runtime code and generate no JavaScript output.

Use these interfaces when you need to write generic code that works with any hash function, any cipher, or any AEAD scheme without depending on a specific implementation. They are available immediately on import with no `init()` call required.

---

## Security Notes

This module contains type definitions only. There are no security-sensitive operations.

---

## API Reference

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

### KeyedHash

```typescript
interface KeyedHash {
  hash(key: Uint8Array, msg: Uint8Array): Uint8Array;
  dispose(): void;
}
```

Interface for keyed hash functions / MACs (e.g., HMAC-SHA256, HMAC-SHA512).

Note: `KeyedHash` does **not** extend `Hash`. Its `hash` method takes a `key` parameter in addition to the message.

| Method | Description |
|---|---|
| `hash(key, msg)` | Computes the keyed hash / MAC over `msg` using `key`. Returns the tag as a new `Uint8Array`. |
| `dispose()` | Releases WASM resources and wipes internal buffers. Call when done. |

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
| `decrypt(ciphertext, aad?)` | Decrypts and verifies the authentication tag. Returns plaintext on success. Throws `Error` on authentication failure — never returns null. |
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

This function accepts any `Hash` implementation -- `SHA256`, `SHA512`, `SHA3_256`, etc. -- without importing any of them directly.

### Accepting any AEAD scheme

```typescript
import type { AEAD } from 'leviathan-crypto'

function sealMessage(aead: AEAD, plaintext: Uint8Array, metadata: Uint8Array): Uint8Array {
  return aead.encrypt(plaintext, metadata)
}

function openMessage(aead: AEAD, ciphertext: Uint8Array, metadata: Uint8Array): Uint8Array {
  // decrypt() throws on auth failure — no null check needed
  return aead.decrypt(ciphertext, metadata)
}
```

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

## Cross-References

- [README.md](./README.md) — library documentation index and exports table
- [architecture.md](./architecture.md) — module structure and correctness contracts
- [utils.md](./utils.md) — encoding utilities and `constantTimeEqual` for verifying MACs from `KeyedHash`
- [serpent.md](./serpent.md) — Serpent classes implement `Blockcipher`, `Streamcipher`, and `AEAD`
- [chacha20.md](./chacha20.md) — ChaCha20/Poly1305 classes implement `Streamcipher` and `AEAD`
- [sha2.md](./sha2.md) — SHA-2 classes implement `Hash`; HMAC classes implement `KeyedHash`
- [sha3.md](./sha3.md) — SHA-3 classes implement `Hash`; SHAKE classes extend with XOF API
- [test-suite.md](./test-suite.md) — test suite structure and vector corpus
