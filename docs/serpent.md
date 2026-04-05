# Serpent-256 block cipher TypeScript API

> [!NOTE]
> `SerpentCipher` is the primary API — use with `Seal`, `SealStream`, and `OpenStream`
> for authenticated Serpent-256 encryption. Lower-level block, CTR, and CBC classes
> are available for advanced use.
>
> See [Serpent implementation audit](./serpent_audit.md) for algorithm correctness verifications.

## Overview

`SerpentCipher` is the primary API for authenticated Serpent-256 encryption. Pass it
to `Seal` for one-shot AEAD, or to `SealStream`/`OpenStream` for streaming — no
manual IV generation, no separate MAC step, no room for misuse. Internally it
uses Encrypt-then-MAC (Serpent-CBC + HMAC-SHA-256) with HKDF key derivation.

For advanced use cases, three lower-level classes are available: `Serpent` (raw
16-byte block operations), `SerpentCtr` (counter mode streaming), and `SerpentCbc`
(cipher block chaining with PKCS7 padding). These are unauthenticated and require
explicit opt-in.

Serpent was an AES finalist. It uses 32 rounds versus AES's 10--14, yielding a
larger security margin at comparable speed in WASM.

---

## Security Notes

> [!IMPORTANT]
> Read this section carefully before using any Serpent class. These are not
> theoretical concerns. Ignoring them will render encryption useless.

### SerpentCbc and SerpentCtr are unauthenticated

This is the most dangerous mistake you can make with this module. An attacker who
can modify ciphertext encrypted with `SerpentCbc` or `SerpentCtr` will produce
corrupted plaintext on decryption -- and decryption will succeed without any
indication of tampering. There is no integrity check. The caller receives garbage
and has no way to distinguish it from the original message.

`Seal` with `SerpentCipher` eliminates this problem. It computes an HMAC tag over
the ciphertext and verifies it before decryption. If anything has been modified,
`Seal.decrypt()` throws instead of returning corrupted data.

`Seal` with `XChaCha20Cipher` is an alternative using a different cipher.
See [chacha20.md](./chacha20.md).

### Never reuse a nonce or IV with the same key

- **CTR mode**: Reusing a nonce with the same key is catastrophic. It produces the
  same keystream, which means an attacker can XOR two ciphertexts together and
  recover both plaintexts. Always generate a fresh random nonce for each message.
- **CBC mode**: The IV (initialization vector) must be random and unpredictable for
  each encryption. A predictable IV enables chosen-plaintext attacks.

Use `randomBytes(16)` to generate nonces and IVs. `Seal` with `SerpentCipher` handles IV
generation internally.

### Always use 256-bit keys

Unless you have a specific reason to use a shorter key, pass a 32-byte key to
every Serpent operation. Shorter keys provide less security margin and there is no
meaningful performance benefit to using them. `SerpentCipher` requires a 32-byte key (HKDF derives enc/mac/iv keys internally).

### Call dispose() when done

Every Serpent class holds key material in WebAssembly memory. When you are finished
with an instance, call `dispose()` to zero out all key material, intermediate
state, and buffers. Failing to call `dispose()` means sensitive data may persist
in memory longer than necessary.

---

## Module Init

Each module subpath exports its own init function for consumers who want
tree-shakeable imports.

### `serpentInit(source)`

Initializes only the serpent WASM binary. Equivalent to calling the
root `init({ serpent: serpentWasm })` but without pulling the other three
modules into the bundle.

**Signature:**

```typescript
async function serpentInit(source: WasmSource): Promise<void>
```

**Usage:**

```typescript
import { serpentInit, Serpent } from 'leviathan-crypto/serpent'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'

await serpentInit(serpentWasm)
const cipher = new Serpent()
```

---

## API Reference

All classes require their WASM modules to be initialized before construction.
`SerpentCipher` (and therefore `Seal`, `SealStream`, `OpenStream`) requires both
`serpent` and `sha2`. `Serpent`, `SerpentCtr`, and `SerpentCbc` require `serpent` only.

### SerpentCipher

`CipherSuite` implementation for Serpent-256 CBC+HMAC-SHA-256. Pass to `Seal`,
`SealStream`, or `OpenStream`. Never instantiated directly.

Requires `init({ serpent: serpentWasm, sha2: sha2Wasm })`.

| Property | Value |
|----------|-------|
| `formatEnum` | `0x02` |
| `keySize` | `32` |
| `tagSize` | `32` (HMAC-SHA-256) |
| `padded` | `true` (PKCS7) |
| `wasmModules` | `['serpent', 'sha2']` |

#### `SerpentCipher.keygen(): Uint8Array`

Returns `randomBytes(32)`. Convenience method — not on the `CipherSuite` interface.

#### Usage with `Seal`

```typescript
import { init, Seal, SerpentCipher } from 'leviathan-crypto'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'
import { sha2Wasm }    from 'leviathan-crypto/sha2/embedded'

await init({ serpent: serpentWasm, sha2: sha2Wasm })

const key  = SerpentCipher.keygen()
const blob = Seal.encrypt(SerpentCipher, key, plaintext)
const pt   = Seal.decrypt(SerpentCipher, key, blob)   // throws on tamper
```

#### Usage with `SealStream` / `OpenStream`

```typescript
import { SealStream, OpenStream } from 'leviathan-crypto/stream'
import { SerpentCipher } from 'leviathan-crypto/serpent'

const sealer   = new SealStream(SerpentCipher, key)
const preamble = sealer.preamble       // 20 bytes — send before first chunk
const ct0      = sealer.push(chunk0)
const ctLast   = sealer.finalize(lastChunk)

const opener = new OpenStream(SerpentCipher, key, preamble)
const pt0    = opener.pull(ct0)
const ptLast = opener.finalize(ctLast)
```

See [stream.md](./stream.md) for the full `Seal`, `SealStream`, and `OpenStream` API.

---

### Serpent

Raw Serpent block encryption and decryption. Operates on exactly 16-byte blocks.
This class is a low-level building block, most users should use `Seal` with
`SerpentCipher` instead.

```typescript
class Serpent {
	constructor()
	loadKey(key: Uint8Array): void
	encryptBlock(plaintext: Uint8Array): Uint8Array
	decryptBlock(ciphertext: Uint8Array): Uint8Array
	dispose(): void
}
```

#### `constructor()`

Creates a new Serpent instance. Throws if `init({ serpent: serpentWasm })` has not been called.

---

#### `loadKey(key: Uint8Array): void`

Loads and expands a key for subsequent block operations. Must be called before
`encryptBlock()` or `decryptBlock()`.

- **key** -- 16, 24, or 32 bytes. Throws `RangeError` if the length is invalid.

---

#### `encryptBlock(plaintext: Uint8Array): Uint8Array`

Encrypts a single 16-byte block and returns the 16-byte ciphertext.

- **plaintext** -- exactly 16 bytes. Throws `RangeError` if the length is not 16.

---

#### `decryptBlock(ciphertext: Uint8Array): Uint8Array`

Decrypts a single 16-byte block and returns the 16-byte plaintext.

- **ciphertext** -- exactly 16 bytes. Throws `RangeError` if the length is not 16.

---

#### `dispose(): void`

Wipes all key material and intermediate state from WASM memory. Always call this
when you are done with the instance.

---

### SerpentCtr

Serpent in Counter (CTR) mode. Encrypts and decrypts data of any length as a
stream of chunks.

> [!WARNING]
> CTR mode is unauthenticated. An attacker can modify ciphertext
> without detection. Use `Seal` with `SerpentCipher` for authenticated encryption, or pair
> with HMAC-SHA256 (Encrypt-then-MAC).

```typescript
class SerpentCtr {
	constructor(opts: { dangerUnauthenticated: true })
	beginEncrypt(key: Uint8Array, nonce: Uint8Array): void
	encryptChunk(chunk: Uint8Array): Uint8Array
	beginDecrypt(key: Uint8Array, nonce: Uint8Array): void
	decryptChunk(chunk: Uint8Array): Uint8Array
	dispose(): void
}
```

#### `constructor(opts: { dangerUnauthenticated: true })`

Creates a new SerpentCtr instance. Throws if `init({ serpent: serpentWasm })` has not been
called. Throws if `{ dangerUnauthenticated: true }` is not passed:

```
leviathan-crypto: SerpentCtr is unauthenticated — use Seal with SerpentCipher instead.
To use SerpentCtr directly, pass { dangerUnauthenticated: true }.
```

---

#### `beginEncrypt(key: Uint8Array, nonce: Uint8Array): void`

Initializes the CTR state for encryption. Loads the key, sets the nonce, and
resets the internal counter to zero.

- **key** -- 16, 24, or 32 bytes. Throws `RangeError` if the length is invalid.
- **nonce** -- exactly 16 bytes. Throws `RangeError` if the length is not 16.

---

#### `encryptChunk(chunk: Uint8Array): Uint8Array`

Encrypts a chunk of plaintext and returns the same-length ciphertext. Call this
one or more times after `beginEncrypt()`. The internal counter advances
automatically.

- **chunk** -- any length up to the module's internal chunk buffer size. Throws
  `RangeError` if the chunk exceeds the maximum size.

> [!NOTE]
> Automatically dispatches to the 4-wide SIMD path (`encryptChunk_simd`) when
> the runtime supports WebAssembly SIMD (`hasSIMD()` returns `true`), otherwise
> falls back to the scalar unrolled path. The dispatch is transparent — no API
> change required.

---

#### `beginDecrypt(key: Uint8Array, nonce: Uint8Array): void`

Initializes the CTR state for decryption. Functionally identical to
`beginEncrypt()` -- CTR mode uses the same operation in both directions.

- **key** -- 16, 24, or 32 bytes. Throws `RangeError` if the length is invalid.
- **nonce** -- exactly 16 bytes. Throws `RangeError` if the length is not 16.

---

#### `decryptChunk(chunk: Uint8Array): Uint8Array`

Decrypts a chunk of ciphertext and returns the same-length plaintext.
Functionally identical to `encryptChunk()`.

- **chunk** -- any length up to the module's internal chunk buffer size. Throws
  `RangeError` if the chunk exceeds the maximum size.

---

#### `dispose(): void`

Wipes all key material and intermediate state from WASM memory.

---

### SerpentCbc

Serpent in Cipher Block Chaining (CBC) mode with automatic PKCS7 padding.
Encrypts and decrypts entire messages in a single call.

> [!WARNING]
> CBC mode is unauthenticated. Always authenticate the output with
> HMAC-SHA256 (Encrypt-then-MAC) or use `Seal` with `SerpentCipher` instead.

```typescript
class SerpentCbc {
	constructor(opts: { dangerUnauthenticated: true })
	encrypt(key: Uint8Array, iv: Uint8Array, plaintext: Uint8Array): Uint8Array
	decrypt(key: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array): Uint8Array
	dispose(): void
}
```

#### `constructor(opts: { dangerUnauthenticated: true })`

Creates a new SerpentCbc instance. Throws if `init({ serpent: serpentWasm })` has not been
called. Throws if `{ dangerUnauthenticated: true }` is not passed:

```
leviathan-crypto: SerpentCbc is unauthenticated — use Seal with SerpentCipher instead.
To use SerpentCbc directly, pass { dangerUnauthenticated: true }.
```

---

#### `encrypt(key: Uint8Array, iv: Uint8Array, plaintext: Uint8Array): Uint8Array`

Encrypts plaintext with Serpent CBC and PKCS7 padding. The returned ciphertext is
always a multiple of 16 bytes and is at least 16 bytes longer than the input (due
to padding).

- **key** -- 16, 24, or 32 bytes. Throws `RangeError` if the length is invalid.
- **iv** -- exactly 16 bytes. Must be random and unique for each (key, message)
  pair. Throws `RangeError` if the length is not 16.
- **plaintext** -- any length (including zero). PKCS7 padding is applied
  automatically.

Returns the ciphertext as a new `Uint8Array`.

---

#### `decrypt(key: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array): Uint8Array`

Decrypts Serpent CBC ciphertext and strips PKCS7 padding.

- **key** -- 16, 24, or 32 bytes. Throws `RangeError` if the length is invalid.
- **iv** -- exactly 16 bytes. Must be the same IV that was used for encryption.
  Throws `RangeError` if the length is not 16.
- **ciphertext** -- must be a non-zero multiple of 16 bytes. Throws `RangeError`
  if the length is zero or not a multiple of 16. Also throws `RangeError` if PKCS7
  padding is invalid (which typically indicates the wrong key, wrong IV, or
  corrupted ciphertext).

Returns the decrypted plaintext as a new `Uint8Array`.

> [!NOTE]
> Automatically dispatches to the 4-wide SIMD path (`cbcDecryptChunk_simd`) when
> the runtime supports WebAssembly SIMD (`hasSIMD()` returns `true`), otherwise
> falls back to the scalar unrolled path. CBC encryption has no SIMD variant —
> each ciphertext block depends on the previous one.

---

#### `dispose(): void`

Wipes all key material and intermediate state from WASM memory.

---

## Usage Examples

### Example 1: Seal with SerpentCipher (authenticated encryption)

```typescript
import { init, Seal, SerpentCipher } from 'leviathan-crypto'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'
import { sha2Wasm }    from 'leviathan-crypto/sha2/embedded'

await init({ serpent: serpentWasm, sha2: sha2Wasm })

const key       = SerpentCipher.keygen()
const plaintext = new TextEncoder().encode('Authenticated secret message.')
const blob      = Seal.encrypt(SerpentCipher, key, plaintext)
const decrypted = Seal.decrypt(SerpentCipher, key, blob)

console.log(new TextDecoder().decode(decrypted))
// "Authenticated secret message."
```

### Example 2: CTR mode (advanced)

Advanced use. For authenticated encryption, use `Seal` with `SerpentCipher`.

Use `SerpentCtr` to encrypt data of any length. CTR mode produces ciphertext
that is the same length as the plaintext -- no padding overhead.

```typescript
import { init, SerpentCtr, randomBytes } from 'leviathan-crypto';
import { serpentWasm } from 'leviathan-crypto/serpent/embedded';

await init({ serpent: serpentWasm });

const key   = randomBytes(32); // 256-bit key
const nonce = randomBytes(16); // 16-byte nonce -- NEVER reuse with the same key

const ctr = new SerpentCtr({ dangerUnauthenticated: true });

// Encrypt
ctr.beginEncrypt(key, nonce);
const ciphertext1 = ctr.encryptChunk(new TextEncoder().encode('Hello, '));
const ciphertext2 = ctr.encryptChunk(new TextEncoder().encode('world!'));

// Decrypt (same key and nonce)
ctr.beginDecrypt(key, nonce);
const plain1 = ctr.decryptChunk(ciphertext1);
const plain2 = ctr.decryptChunk(ciphertext2);

console.log(new TextDecoder().decode(plain1)); // "Hello, "
console.log(new TextDecoder().decode(plain2)); // "world!"

// Wipe key material
ctr.dispose();
```

> [!IMPORTANT]
> CTR mode is unauthenticated. An attacker can tamper with the
> ciphertext without detection. Use `Seal` with `SerpentCipher` for authenticated encryption.

### Example 3: CBC mode (advanced)

Advanced use. For authenticated encryption, use `Seal` with `SerpentCipher`.

Use `SerpentCbc` for message-level encryption with automatic PKCS7 padding.

```typescript
import { init, SerpentCbc, randomBytes } from 'leviathan-crypto';
import { serpentWasm } from 'leviathan-crypto/serpent/embedded';

await init({ serpent: serpentWasm });

const key = randomBytes(32); // 256-bit key
const iv  = randomBytes(16); // Random IV -- must be unique per message

const cbc = new SerpentCbc({ dangerUnauthenticated: true });

// Encrypt
const plaintext  = new TextEncoder().encode('This is a secret message.');
const ciphertext = cbc.encrypt(key, iv, plaintext);

// Decrypt
const decrypted = cbc.decrypt(key, iv, ciphertext);
console.log(new TextDecoder().decode(decrypted)); // "This is a secret message."

// Wipe key material
cbc.dispose();
```

> [!IMPORTANT]
> CBC mode is unauthenticated. Use `Seal` with `SerpentCipher` for authenticated encryption.

### Example 4: Raw block operations (low-level)

Use the `Serpent` class for single 16-byte block operations. This is the lowest
level API, most users should use `Seal` with `SerpentCipher` instead.

```typescript
import { init, Serpent } from 'leviathan-crypto';
import { serpentWasm } from 'leviathan-crypto/serpent/embedded';

await init({ serpent: serpentWasm });

const cipher = new Serpent();

// Load a 256-bit key (32 bytes)
const key = new Uint8Array(32);
crypto.getRandomValues(key);
cipher.loadKey(key);

// Encrypt a 16-byte block
const plaintext = new Uint8Array([
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
]);
const ciphertext = cipher.encryptBlock(plaintext);

// Decrypt it back
const decrypted = cipher.decryptBlock(ciphertext);
// decrypted is identical to plaintext

// Wipe key material from memory when done
cipher.dispose();
```

---

## Error Conditions

| Condition | Error type | Message |
|-----------|-----------|---------|
| `init({ serpent: ... })` not called before constructing `Serpent` | `Error` | `leviathan-crypto: call init({ serpent: ... }) before using this class` |
| `SerpentCbc` constructed without `{ dangerUnauthenticated: true }` | `Error` | `leviathan-crypto: SerpentCbc is unauthenticated — use Seal with SerpentCipher instead. To use SerpentCbc directly, pass { dangerUnauthenticated: true }.` |
| `SerpentCtr` constructed without `{ dangerUnauthenticated: true }` | `Error` | `leviathan-crypto: SerpentCtr is unauthenticated — use Seal with SerpentCipher instead. To use SerpentCtr directly, pass { dangerUnauthenticated: true }.` |
| Key is not 16, 24, or 32 bytes (`Serpent.loadKey`) | `RangeError` | `key must be 16, 24, or 32 bytes (got N)` |
| Key is not 16, 24, or 32 bytes (`SerpentCbc`) | `RangeError` | `Serpent key must be 16, 24, or 32 bytes (got N)` |
| Key is not 16, 24, or 32 bytes (`SerpentCtr`) | `RangeError` | `key must be 16, 24, or 32 bytes` |
| Block is not 16 bytes (`Serpent`) | `RangeError` | `block must be 16 bytes (got N)` |
| Nonce is not 16 bytes (`SerpentCtr`) | `RangeError` | `nonce must be 16 bytes (got N)` |
| Chunk exceeds buffer size (`SerpentCtr`) | `RangeError` | `chunk exceeds maximum size of N bytes — split into smaller chunks` |
| IV is not 16 bytes (`SerpentCbc`) | `RangeError` | `CBC IV must be 16 bytes (got N)` |
| Ciphertext length is zero or not a multiple of 16 (`SerpentCbc.decrypt`) | `RangeError` | `ciphertext length must be a non-zero multiple of 16` |
| Invalid PKCS7 padding on decrypt (`SerpentCbc.decrypt`) | `RangeError` | `invalid PKCS7 padding` |

---

> ## Cross-References
>
> - [index](./README.md) — Project Documentation index
> - [architecture](./architecture.md) — architecture overview, module relationships, buffer layouts, and build pipeline
> - [asm_serpent](./asm_serpent.md) — WASM implementation details and buffer layout
> - [serpent_reference](./serpent_reference.md) — algorithm specification, S-boxes, linear transform, and known attacks
> - [serpent_audit](./serpent_audit.md) — security audit findings (correctness, side-channel analysis)
> - [stream](./stream.md) — `Seal`, `SealStream`, `OpenStream`: use `SerpentCipher` as the suite argument
> - [chacha20](./chacha20.md) — `XChaCha20Cipher`: alternative `CipherSuite` for `Seal` and streaming
> - [sha2](./sha2.md) — HMAC-SHA256 and HKDF used internally by `SerpentCipher`
> - [types](./types.md) — `Blockcipher`, `Streamcipher`, and `AEAD` interfaces implemented by Serpent classes
> - [utils](./utils.md) — `constantTimeEqual`, `wipe`, `randomBytes` used by Serpent wrappers

