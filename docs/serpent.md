<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### Serpent-256 TypeScript API

See [Serpent implementation audit](./serpent_audit.md) for algorithm correctness verifications.

> ### Table of Contents
> - [Overview](#overview)
> - [Security Notes](#security-notes)
> - [Module Init](#module-init)
> - [API Reference](#api-reference)
> - [SerpentGenerator](#serpentgenerator)
> - [Usage Examples](#usage-examples)
> - [Error Conditions](#error-conditions)

---

## Overview

`SerpentCipher` is the primary API for authenticated Serpent-256 encryption. Pass it
to `Seal` for one-shot AEAD, or to `SealStream`/`OpenStream` for streaming. There is
no manual IV generation, no separate MAC step, and no room for misuse. Internally it
uses Encrypt-then-MAC (Serpent-CBC + HMAC-SHA-256) with HKDF key derivation.

For advanced use cases, three lower-level classes are available: `Serpent` (raw
16-byte block operations), `SerpentCtr` (counter mode streaming), and `SerpentCbc`
(cipher block chaining with PKCS7 padding). These are unauthenticated and require
explicit opt-in.

Serpent was an AES finalist. It uses 32 rounds versus AES's 10 to 14, yielding a
larger security margin at comparable speed in WASM.

---

## Security Notes

> [!IMPORTANT]
> Read this section carefully before using any Serpent class. These are not
> theoretical concerns. Ignoring them will render encryption useless.

### SerpentCbc and SerpentCtr are unauthenticated

This is the most dangerous mistake you can make with this module. An attacker who
can modify ciphertext encrypted with `SerpentCbc` or `SerpentCtr` will produce
corrupted plaintext on decryption. Decryption succeeds without any indication of
tampering. There is no integrity check. Your caller receives garbage and has no way
to distinguish it from the original message.

[`Seal`](./aead.md#seal) with [`SerpentCipher`](./ciphersuite.md#serpentcipher)
eliminates this problem. It computes an HMAC tag over the ciphertext and
verifies it before decryption. If anything has been modified, `Seal.decrypt()`
throws instead of returning corrupted data.

### Never reuse a nonce or IV with the same key

In CTR mode, reusing a nonce with the same key is catastrophic. It produces the
same keystream, which means an attacker can XOR two ciphertexts together and
recover both plaintexts. Always generate a fresh random nonce for each message.
In CBC mode, the IV must be random and unpredictable for each encryption. A predictable IV enables chosen-plaintext attacks.

Use `randomBytes(16)` to generate nonces and IVs. [`Seal`](./aead.md#seal) with [`SerpentCipher`](./ciphersuite.md#serpentcipher) handles IV generation internally.

### Always use 256-bit keys

Unless you have a specific reason to use a shorter key, pass a 32-byte key to
every Serpent operation. Shorter keys provide less security margin and there is no
meaningful performance benefit to using them. [`SerpentCipher`](./ciphersuite.md#serpentcipher) requires a 32-byte key; HKDF derives enc/mac/iv keys internally.

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

Returns `randomBytes(32)`. Convenience method. Not on the [`CipherSuite`](./ciphersuite.md) interface.

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
const preamble = sealer.preamble       // 20 bytes, send before first chunk
const ct0      = sealer.push(chunk0)
const ctLast   = sealer.finalize(lastChunk)

const opener = new OpenStream(SerpentCipher, key, preamble)
const pt0    = opener.pull(ct0)
const ptLast = opener.finalize(ctLast)
```

See [aead.md](./aead.md) for the full `Seal`, `SealStream`, and `OpenStream` API.

---

### Serpent

Raw Serpent block encryption and decryption. Operates on exactly 16-byte blocks.
This class is a low-level building block

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

- **key**: 16, 24, or 32 bytes. Throws `RangeError` if the length is invalid.

---

#### `encryptBlock(plaintext: Uint8Array): Uint8Array`

Encrypts a single 16-byte block and returns the 16-byte ciphertext.

- **plaintext**: exactly 16 bytes. Throws `RangeError` if the length is not 16.

---

#### `decryptBlock(ciphertext: Uint8Array): Uint8Array`

Decrypts a single 16-byte block and returns the 16-byte plaintext.

- **ciphertext**: exactly 16 bytes. Throws `RangeError` if the length is not 16.

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
> without detection. Use [`Seal`](./aead.md#seal) with [`SerpentCipher`](./ciphersuite.md#serpentcipher) for authenticated encryption, or pair
> with HMAC-SHA256 (Encrypt-then-MAC).

> [!CAUTION]
> `SerpentCtr` is stateful and holds exclusive access to the `serpent` WASM
> module for its entire lifetime. Constructing a second `SerpentCtr`/
> `SerpentCbc`, `SerpentCipher` usage (`Seal.encrypt(SerpentCipher, ...)`,
> `SealStream` with `SerpentCipher`), or any atomic serpent class
> (`Serpent` block) while this instance is live throws. Call `dispose()`
> when done. Pool workers are unaffected.

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

- **key**: 16, 24, or 32 bytes. Throws `RangeError` if the length is invalid.
- **nonce**: exactly 16 bytes. Throws `RangeError` if the length is not 16.

---

#### `encryptChunk(chunk: Uint8Array): Uint8Array`

Encrypts a chunk of plaintext and returns the same-length ciphertext. Call this
one or more times after `beginEncrypt()`. The internal counter advances
automatically.

- **chunk**: any length up to the module's internal chunk buffer size. Throws `RangeError` if the chunk exceeds the maximum size.

> [!NOTE]
> Always uses the 4-wide SIMD path (`encryptChunk_simd`). SIMD is required by the serpent module; `init()` throws on runtimes without WebAssembly SIMD support.

---

#### `beginDecrypt(key: Uint8Array, nonce: Uint8Array): void`

Initializes the CTR state for decryption. Functionally identical to `beginEncrypt()`. CTR mode uses the same operation in both directions.

- **key**: 16, 24, or 32 bytes. Throws `RangeError` if the length is invalid.
- **nonce**: exactly 16 bytes. Throws `RangeError` if the length is not 16.

---

#### `decryptChunk(chunk: Uint8Array): Uint8Array`

Decrypts a chunk of ciphertext and returns the same-length plaintext.
Functionally identical to `encryptChunk()`.

- **chunk**: any length up to the module's internal chunk buffer size. Throws `RangeError` if the chunk exceeds the maximum size.

---

#### `dispose(): void`

Wipes all key material and intermediate state from WASM memory.

After `dispose()`, all instance methods (`beginEncrypt`, `encryptChunk`,
`beginDecrypt`, `decryptChunk`) throw `Error: SerpentCtr: instance has been
disposed`. Disposal is permanent; construct a new instance if you need to
continue.

---

### SerpentCbc

Serpent in Cipher Block Chaining (CBC) mode with automatic PKCS7 padding.
Encrypts and decrypts entire messages in a single call.

> [!WARNING]
> CBC mode is unauthenticated. Always authenticate the output with
> HMAC-SHA256 (Encrypt-then-MAC) or use [`Seal`](./aead.md#seal) with [`SerpentCipher`](./ciphersuite.md#serpentcipher) instead.

> [!CAUTION]
> `SerpentCbc` is stateful and holds exclusive access to the `serpent` WASM
> module for its entire lifetime. Constructing a second `SerpentCbc`/
> `SerpentCtr`, `SerpentCipher` usage (which internally constructs a
> `SerpentCbc`), or any atomic serpent class (`Serpent` block) while this
> instance is live throws. Call `dispose()` when done.

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

- **key**: 16, 24, or 32 bytes. Throws `RangeError` if the length is invalid.
- **iv**: exactly 16 bytes. Must be random and unique per (key, message) pair. Throws `RangeError` if the length is not 16.
- **plaintext**: any length including zero. PKCS7 padding is applied automatically.

Returns the ciphertext as a new `Uint8Array`.

---

#### `decrypt(key: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array): Uint8Array`

Decrypts Serpent CBC ciphertext and strips PKCS7 padding.

- **key**: 16, 24, or 32 bytes. Throws `RangeError` if the length is invalid.
- **iv**: exactly 16 bytes. Must match the IV used for encryption. Throws `RangeError` if the length is not 16.
- **ciphertext**: must be a non-zero multiple of 16 bytes. Throws `RangeError` with the generic message `'invalid ciphertext'` on any failure — zero length, non-multiple-of-16 length, or invalid PKCS7 padding. The single message and branch-free padding check close the Vaudenay 2002 padding-oracle surface; a caller cannot distinguish failure modes by message or by timing.

Returns the decrypted plaintext as a new `Uint8Array`.

> [!NOTE]
> Decryption always uses the 4-wide SIMD path (`cbcDecryptChunk_simd`). SIMD is required by the serpent module; `init()` throws on runtimes without it. CBC encryption has no SIMD variant because each ciphertext block depends on the previous one.

---

#### `dispose(): void`

Wipes all key material and intermediate state from WASM memory.

After `dispose()`, `encrypt` and `decrypt` throw `Error: SerpentCbc: instance
has been disposed`. Disposal is permanent; construct a new instance if you
need to continue.

---

### Security — direct use of `SerpentCbc`

`SerpentCbc` is unauthenticated. If you use it directly via
`{ dangerUnauthenticated: true }`, you are responsible for:

1. Authenticating the ciphertext (HMAC-SHA256 in Encrypt-then-MAC order)
2. Verifying the HMAC **before** calling `decrypt()`
3. Using a unique, random IV per (key, message)

`SerpentCbc.decrypt()` throws a single generic `'invalid ciphertext'`
error for all padding failures and runs its validation in constant time over the
final 16 bytes. This mitigates padding-oracle attacks (Vaudenay 2002) on callers
that surface errors to remote parties. The authenticated composition
`SerpentCipher` always verifies HMAC before any PKCS7 processing and is the
recommended path.

---

## SerpentGenerator

Serpent-256 ECB counter-mode PRF for Fortuna's generator slot. Implements the
`Generator` interface (Practical Cryptography, Ferguson & Schneier 2003 §9.4).
This is a plain `const` object, not a class — no instantiation, no `dispose()`.

Requires `init({ serpent: serpentWasm })`. See [fortuna.md](./fortuna.md) for
full usage with `Fortuna.create()`.

| Property | Value |
|----------|-------|
| `keySize` | `32` |
| `blockSize` | `16` |
| `counterSize` | `16` |
| `wasmModules` | `['serpent']` |

### `SerpentGenerator.generate(key, counter, n): Uint8Array`

Produces `n` bytes of pseudorandom output from `(key, counter)`. Neither input
is mutated. Wipes WASM key/key-schedule/scratch and the JS-heap counter copy
before returning.

| Parameter | Type | Description |
|-----------|------|-------------|
| `key` | `Uint8Array` | 32 bytes (256-bit Serpent key) |
| `counter` | `Uint8Array` | 16 bytes, treated as a little-endian integer |
| `n` | `number` | Output byte count: 0 ≤ n ≤ 2³⁰ |

**Returns** a new `Uint8Array` of length `n`.

**Throws:**
- `RangeError('SerpentGenerator: key must be 32 bytes (got N)')` if key length ≠ 32
- `RangeError('SerpentGenerator: counter must be 16 bytes (got N)')` if counter length ≠ 16
- `RangeError('SerpentGenerator: n must be a non-negative safe integer <= 2^30 (got N)')` if n is out of range
- `Error` if another stateful instance currently owns the `serpent` WASM module

### Usage with `Fortuna`

```typescript
import { init, Fortuna } from 'leviathan-crypto'
import { SerpentGenerator } from 'leviathan-crypto/serpent'
import { SHA256Hash } from 'leviathan-crypto/sha2'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await init({ serpent: serpentWasm, sha2: sha2Wasm })
const rng = await Fortuna.create({ generator: SerpentGenerator, hash: SHA256Hash })
const bytes = rng.get(32)
rng.stop()
```

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

Use `SerpentCtr` to encrypt data of any length. CTR mode produces ciphertext
the same length as the plaintext with no padding overhead.

```typescript
import { init, SerpentCtr, randomBytes } from 'leviathan-crypto';
import { serpentWasm } from 'leviathan-crypto/serpent/embedded';

await init({ serpent: serpentWasm });

const key   = randomBytes(32); // 256-bit key
const nonce = randomBytes(16); // 16-byte nonce, NEVER reuse with the same key

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
> ciphertext without detection. Use  [`Seal`](./aead.md#seal) with [`SerpentCipher`](./ciphersuite.md#serpentcipher) for authenticated encryption.

### Example 3: CBC mode (advanced)

Use `SerpentCbc` for message-level encryption with automatic PKCS7 padding.

```typescript
import { init, SerpentCbc, randomBytes } from 'leviathan-crypto';
import { serpentWasm } from 'leviathan-crypto/serpent/embedded';

await init({ serpent: serpentWasm });

const key = randomBytes(32); // 256-bit key
const iv  = randomBytes(16); // Random IV, must be unique per message

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
> CBC mode is unauthenticated. Use [`Seal`](./aead.md#seal) with [`SerpentCipher`](./ciphersuite.md#serpentcipher) for authenticated encryption.

### Example 4: Raw block operations (low-level)

Use the `Serpent` class for single 16-byte block operations. This is the lowest-level

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
| Ciphertext length zero, not a multiple of 16, or PKCS7 padding invalid (`SerpentCbc.decrypt`) | `RangeError` | `invalid ciphertext` (same message for every failure mode — no numeric leak) |
| `SerpentGenerator.generate()` key ≠ 32 bytes | `RangeError` | `SerpentGenerator: key must be 32 bytes (got N)` |
| `SerpentGenerator.generate()` counter ≠ 16 bytes | `RangeError` | `SerpentGenerator: counter must be 16 bytes (got N)` |
| `SerpentGenerator.generate()` n out of range | `RangeError` | `SerpentGenerator: n must be a non-negative safe integer <= 2^30 (got N)` |

---


## Cross-References

| Document | Description |
| -------- | ----------- |
| [index](./README.md) | Project Documentation index |
| [lexicon](./lexicon.md) | Glossary of cryptographic terms |
| [architecture](./architecture.md) | architecture overview, module relationships, buffer layouts, and build pipeline |
| [asm_serpent](./asm_serpent.md) | WASM implementation details and buffer layout |
| [serpent_reference](./serpent_reference.md) | algorithm specification, S-boxes, linear transform, and known attacks |
| [serpent_audit](./serpent_audit.md) | security audit findings (correctness, side-channel analysis) |
| [authenticated encryption](./aead.md) | `Seal`, `SealStream`, `OpenStream`: use `SerpentCipher` as the suite argument |
| [chacha20](./chacha20.md) | `XChaCha20Cipher`: alternative `CipherSuite` for `Seal` and streaming |
| [sha2](./sha2.md) | HMAC-SHA256 and HKDF used internally by `SerpentCipher` |
| [types](./types.md) | `Blockcipher`, `Streamcipher`, and `AEAD` interfaces implemented by Serpent classes |
| [utils](./utils.md) | `constantTimeEqual`, `wipe`, `randomBytes` used by Serpent wrappers |

