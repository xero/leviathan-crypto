# ChaCha20, Poly1305, and AEAD TypeScript API

> [!NOTE]
> See [ChaCha20-Poly1305 implementation audit](./chacha_audit.md) for algorithm correctness verifications.

## Overview

**ChaCha20** is a modern stream cipher designed by Daniel J. Bernstein. It is fast
on all platforms (including those without hardware AES), resistant to timing attacks
by design, and widely deployed in TLS, SSH, and WireGuard. ChaCha20 encrypts data
by generating a pseudorandom keystream from a 256-bit key and a nonce, then XORing
it with the plaintext. It does **not** provide authentication on its own — a
modified message will decrypt to garbage with no warning.

**Poly1305** is a one-time message authentication code (MAC). Given a unique 256-bit
key and a message, it produces a 16-byte tag that proves the message has not been
tampered with. The critical requirement is that each Poly1305 key is used **exactly
once** — reusing a key completely breaks its security. You almost never need to use
Poly1305 directly; the AEAD constructions below handle key derivation for you.

**ChaCha20-Poly1305** (RFC 8439) combines both primitives into an AEAD
(Authenticated Encryption with Associated Data). It encrypts your data and
produces an authentication tag in a single operation. On decryption, it verifies
the tag before returning any plaintext — if someone tampered with the ciphertext,
you get an error instead of corrupted data. The nonce is 96 bits (12 bytes).

**XChaCha20-Poly1305** extends the nonce to 192 bits (24 bytes) using the HChaCha20
subkey derivation step. This makes random nonce generation completely safe — with a
24-byte nonce, the probability of a collision is negligible even after billions of
messages. **For most users, `XChaCha20Seal` is the recommended choice.** It binds the key
at construction, generates a fresh nonce per call, and provides the simplest
correct API. For protocol interop requiring explicit nonce control, use
`XChaCha20Poly1305` directly.

## Security Notes

> [!IMPORTANT]
> Read this section before writing any code. These are not theoretical concerns —
> they are the mistakes that cause real-world breaches.

- **Use `XChaCha20Seal` unless you need explicit nonce control.** It is the
  safest default: authenticated encryption with automatic nonce generation.
  If you are unsure which class to pick, pick this one. Use `XChaCha20Poly1305`
  when protocol interop requires you to manage nonces yourself.

- **Never reuse a nonce with the same key.** This is the single most important
  rule. If you encrypt two different messages with the same key and the same nonce,
  an attacker can XOR the two ciphertexts together and recover both plaintexts.
  With `ChaCha20Poly1305` (12-byte nonce), random generation has a meaningful
  collision risk after roughly 2^32 messages under one key. With
  `XChaCha20Poly1305` (24-byte nonce), random generation is safe for any practical
  message count — just call `randomBytes(24)` for each message.

- **Poly1305 keys are single-use.** Each Poly1305 key must be used to authenticate
  exactly one message. The AEAD classes (`ChaCha20Poly1305` and
  `XChaCha20Poly1305`) handle this automatically by deriving a fresh Poly1305 key
  from the ChaCha20 keystream for each encryption. If you use the standalone
  `Poly1305` class directly, it is your responsibility to never reuse a key.

- **AEAD protects both confidentiality and authenticity.** If authentication fails
  during decryption, the plaintext is never returned — you get an error. This is
  intentional. Do not try to work around it. If decryption fails, the ciphertext
  was corrupted or tampered with.

- **Associated data (AAD) is authenticated but not encrypted.** Use AAD for data
  that must travel in the clear (headers, routing metadata, user IDs) but must be
  verified as unmodified. If someone changes the AAD, decryption will fail — even
  if the ciphertext itself is untouched.

- **Always call `dispose()` when you are done.** This wipes key material and
  intermediate state from WASM memory. Failing to call `dispose()` leaves
  sensitive data in memory longer than necessary.

- **`ChaCha20` alone has no authentication.** If you use the raw `ChaCha20` class
  without pairing it with a MAC, an attacker can flip bits in the ciphertext and
  the corresponding bits in the plaintext will flip silently. Unless you are
  building your own authenticated construction (and you probably should not be),
  use one of the AEAD classes instead.

## Module Init

Each module subpath exports its own init function for consumers who want
tree-shakeable imports.

### `chacha20Init(source)`

Initializes only the chacha20 WASM binary. Equivalent to calling the
root `init({ chacha20: chacha20Wasm })` but without pulling the other three
modules into the bundle.

**Signature:**

```typescript
async function chacha20Init(source: WasmSource): Promise<void>
```

**Usage:**

```typescript
import { chacha20Init, XChaCha20Poly1305 } from 'leviathan-crypto/chacha20'
import { chacha20Wasm } from 'leviathan-crypto/chacha20/embedded'

await chacha20Init(chacha20Wasm)
const aead = new XChaCha20Poly1305()
```

---

## API Reference

All classes require calling `await init({ chacha20: chacha20Wasm })` or the subpath `chacha20Init()`
before construction. If you construct a class before initialization, it throws:
```
Error: leviathan-crypto: call init({ chacha20: ... }) before using this class
```

---

### `ChaCha20`

Raw ChaCha20 stream cipher. **No authentication** — use `XChaCha20Poly1305` instead
unless you are building a custom protocol and understand the risks.

#### Constructor

```typescript
new ChaCha20()
```

Throws if `init({ chacha20: chacha20Wasm })` has not been called.

---

#### `beginEncrypt(key: Uint8Array, nonce: Uint8Array): void`

Prepares the cipher for encryption with the given key and nonce.

| Parameter | Type | Description |
|-----------|------|-------------|
| `key` | `Uint8Array` | 32 bytes (256 bits) |
| `nonce` | `Uint8Array` | 12 bytes (96 bits) |

**Throws** `RangeError` if `key` is not 32 bytes or `nonce` is not 12 bytes.

---

#### `encryptChunk(chunk: Uint8Array): Uint8Array`

Encrypts a chunk of plaintext. Call repeatedly for streaming encryption. Returns
a new `Uint8Array` containing the ciphertext (same length as input).

| Parameter | Type | Description |
|-----------|------|-------------|
| `chunk` | `Uint8Array` | Plaintext bytes (up to the module's chunk size limit) |

**Throws** `RangeError` if the chunk exceeds the maximum chunk size.

---

#### `beginDecrypt(key: Uint8Array, nonce: Uint8Array): void`

Prepares the cipher for decryption. Identical to `beginEncrypt` — ChaCha20 is
symmetric (encryption and decryption are the same XOR operation).

| Parameter | Type | Description |
|-----------|------|-------------|
| `key` | `Uint8Array` | 32 bytes (256 bits) |
| `nonce` | `Uint8Array` | 12 bytes (96 bits) |

**Throws** `RangeError` if `key` is not 32 bytes or `nonce` is not 12 bytes.

---

#### `decryptChunk(chunk: Uint8Array): Uint8Array`

Decrypts a chunk of ciphertext. Returns a new `Uint8Array` containing the
plaintext (same length as input).

| Parameter | Type | Description |
|-----------|------|-------------|
| `chunk` | `Uint8Array` | Ciphertext bytes |

**Throws** `RangeError` if the chunk exceeds the maximum chunk size.

---

#### `dispose(): void`

Wipes all key material and intermediate state from WASM memory. Always call this
when you are done with the instance.

---

### `Poly1305`

Standalone Poly1305 one-time MAC. **Each key must be used exactly once.** You
almost certainly want `ChaCha20Poly1305` or `XChaCha20Poly1305` instead — they
handle Poly1305 key derivation automatically.

#### Constructor

```typescript
new Poly1305()
```

Throws if `init({ chacha20: chacha20Wasm })` has not been called.

---

#### `mac(key: Uint8Array, msg: Uint8Array): Uint8Array`

Computes a 16-byte Poly1305 authentication tag over the given message.

| Parameter | Type | Description |
|-----------|------|-------------|
| `key` | `Uint8Array` | 32 bytes — must be unique per message |
| `msg` | `Uint8Array` | The message to authenticate (any length) |

**Returns** `Uint8Array` — a 16-byte authentication tag.

**Throws** `RangeError` if `key` is not 32 bytes.

---

#### `dispose(): void`

Wipes all key material and intermediate state from WASM memory.

---

### `ChaCha20Poly1305`

ChaCha20-Poly1305 AEAD as specified in RFC 8439. Provides authenticated encryption
with a 12-byte (96-bit) nonce. The Poly1305 one-time key is derived automatically
from the ChaCha20 keystream (counter 0).

If you are generating nonces randomly, prefer `XChaCha20Poly1305` (24-byte nonce)
to avoid collision risk.

#### Constructor

```typescript
new ChaCha20Poly1305()
```

Throws if `init({ chacha20: chacha20Wasm })` has not been called.

---

#### `encrypt(key, nonce, plaintext, aad?): Uint8Array`

Encrypts plaintext and returns the ciphertext with the 16-byte Poly1305 tag
appended.

> [!WARNING]
> Each `ChaCha20Poly1305` instance allows only **one** `encrypt()` call. A second
> call throws to prevent accidental nonce reuse. Create a new instance for each
> encryption, or use `XChaCha20Seal` for automatic nonce management.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `key` | `Uint8Array` | | 32 bytes (256-bit key) |
| `nonce` | `Uint8Array` | | 12 bytes (96-bit nonce) |
| `plaintext` | `Uint8Array` | | Data to encrypt (up to the module's chunk size limit) |
| `aad` | `Uint8Array` | `new Uint8Array(0)` | Associated data — authenticated but not encrypted |

**Returns** `Uint8Array` — ciphertext + 16-byte tag (length = plaintext.length + 16).

**Throws:**
- `RangeError` if `key` is not 32 bytes
- `RangeError` if `nonce` is not 12 bytes
- `RangeError` if `plaintext` exceeds the maximum chunk size
- `Error` if `encrypt()` has already been called on this instance

---

#### `decrypt(key, nonce, ciphertext, aad?): Uint8Array`

Verifies the authentication tag and decrypts the ciphertext. The `ciphertext`
parameter must include the appended 16-byte tag (i.e., the exact output of
`encrypt()`). If authentication fails, an error is thrown and no plaintext is
returned.

Tag comparison uses a constant-time XOR-accumulate pattern — no timing side
channel leaks whether the tag was "close" to correct.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `key` | `Uint8Array` | | 32 bytes (same key used for encryption) |
| `nonce` | `Uint8Array` | | 12 bytes (same nonce used for encryption) |
| `ciphertext` | `Uint8Array` | | Encrypted data with appended tag (output of `encrypt()`) |
| `aad` | `Uint8Array` | `new Uint8Array(0)` | Associated data (must match what was passed to `encrypt()`) |

**Returns** `Uint8Array` — the decrypted plaintext.

**Throws:**
- `RangeError` if `key` is not 32 bytes
- `RangeError` if `nonce` is not 12 bytes
- `RangeError` if `ciphertext` is shorter than 16 bytes (no room for a tag)
- `Error('ChaCha20Poly1305: authentication failed')` if the tag does not match

---

#### `dispose(): void`

Wipes all key material and intermediate state from WASM memory.

---

### `XChaCha20Poly1305`

XChaCha20-Poly1305 AEAD (draft-irtf-cfrg-xchacha). RFC-faithful stateless
primitive — key and nonce are passed per-call. Use when protocol interop
requires explicit nonce control. For most use cases, prefer `XChaCha20Seal`
(bound key, automatic nonce management).

It uses a 24-byte (192-bit) nonce, which is large enough that randomly generated
nonces will never collide in practice. Internally, it derives a subkey via
HChaCha20 and delegates to `ChaCha20Poly1305`.

Like `ChaCha20Poly1305`, the `encrypt()` method returns a single `Uint8Array`
with the tag appended to the ciphertext. The `decrypt()` method expects this
combined format and splits it internally.

#### Constructor

```typescript
new XChaCha20Poly1305()
```

Throws if `init({ chacha20: chacha20Wasm })` has not been called.

---

#### `encrypt(key, nonce, plaintext, aad?): Uint8Array`

Encrypts plaintext and returns the ciphertext with the 16-byte tag appended.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `key` | `Uint8Array` | | 32 bytes (256-bit key) |
| `nonce` | `Uint8Array` | | 24 bytes (192-bit nonce) |
| `plaintext` | `Uint8Array` | | Data to encrypt |
| `aad` | `Uint8Array` | `new Uint8Array(0)` | Associated data — authenticated but not encrypted |

**Returns** `Uint8Array` — ciphertext + 16-byte tag (length = plaintext.length + 16).

**Throws:**
- `RangeError` if `key` is not 32 bytes
- `RangeError` if `nonce` is not 24 bytes

---

#### `decrypt(key, nonce, ciphertext, aad?): Uint8Array`

Verifies the authentication tag and decrypts the ciphertext. The `ciphertext`
parameter must include the appended 16-byte tag (i.e., the exact output of
`encrypt()`).

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `key` | `Uint8Array` | | 32 bytes (same key used for encryption) |
| `nonce` | `Uint8Array` | | 24 bytes (same nonce used for encryption) |
| `ciphertext` | `Uint8Array` | | Encrypted data with appended tag (output of `encrypt()`) |
| `aad` | `Uint8Array` | `new Uint8Array(0)` | Associated data (must match what was passed to `encrypt()`) |

**Returns** `Uint8Array` — the decrypted plaintext.

**Throws:**
- `RangeError` if `key` is not 32 bytes
- `RangeError` if `nonce` is not 24 bytes
- `RangeError` if `ciphertext` is shorter than 16 bytes (no room for a tag)
- `Error('ChaCha20Poly1305: authentication failed')` if the tag does not match

---

#### `dispose(): void`

Wipes all key material and intermediate state from WASM memory.

---

## `XChaCha20Seal`

XChaCha20-Poly1305 AEAD with a bound key and automatic nonce management.
**This is the recommended authenticated encryption class.** It implements the
`AEAD` interface — `encrypt()` and `decrypt()` require only plaintext and
optional AAD. Each `encrypt()` call generates a fresh 24-byte random nonce
internally, eliminating any risk of nonce reuse.

**Wire format:** `nonce(24) || ciphertext || tag(16)`

> [!NOTE]
> The nonce is generated internally via `crypto.getRandomValues` — you never
> need to manage nonces. For protocol interop requiring explicit nonce control,
> use `XChaCha20Poly1305` directly.

#### Constructor

```typescript
new XChaCha20Seal(key: Uint8Array)   // 32 bytes
```

Binds the key at construction. Throws if `init({ chacha20: chacha20Wasm })` has not been
called. Throws `RangeError` if key is not 32 bytes. The key is copied
internally — the caller's buffer can be wiped after construction.

---

#### `encrypt(plaintext, aad?): Uint8Array`

Encrypts plaintext and returns a sealed blob with nonce prepended and tag
appended.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `plaintext` | `Uint8Array` | | Data to encrypt (any length, including empty) |
| `aad` | `Uint8Array` | `new Uint8Array(0)` | Associated data — authenticated but not encrypted |

**Returns** `Uint8Array` — `nonce(24) || ciphertext || tag(16)` (length = plaintext.length + 40).

---

#### `decrypt(ciphertext, aad?): Uint8Array`

Reads the nonce from the first 24 bytes, verifies the tag, and decrypts.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `ciphertext` | `Uint8Array` | | Sealed blob from `encrypt()` |
| `aad` | `Uint8Array` | `new Uint8Array(0)` | Associated data (must match what was passed to `encrypt()`) |

**Returns** `Uint8Array` — the decrypted plaintext.

**Throws:**
- `RangeError` if `ciphertext` is shorter than 40 bytes (nonce + tag minimum)
- `Error('ChaCha20Poly1305: authentication failed')` if the tag does not match

---

#### `dispose(): void`

Wipes the key copy and all WASM buffers.

---

#### Usage

```typescript
await init({ chacha20: chacha20Wasm })
const key  = randomBytes(32)
const seal = new XChaCha20Seal(key)
const ct   = seal.encrypt(plaintext)               // nonce generated internally
const pt   = seal.decrypt(ct)                       // throws on tamper
seal.dispose()
```

---

## XChaCha20Cipher

`CipherSuite` implementation for XChaCha20-Poly1305. Used with `SealStream` and `OpenStream` for streaming encryption.

```ts
import { SealStream } from 'leviathan-crypto/stream';
import { XChaCha20Cipher } from 'leviathan-crypto/chacha20';

const sealer = new SealStream(XChaCha20Cipher, key);
```

| Property | Value |
|----------|-------|
| `formatEnum` | `0x01` |
| `keySize` | `32` |
| `tagSize` | `16` (Poly1305) |
| `padded` | `false` |
| `wasmModules` | `['chacha20']` |

> [!NOTE]
> The stream layer requires `sha2` for HKDF key derivation. Initialize both
> modules: `init({ chacha20: chacha20Wasm, sha2: sha2Wasm })`.

See stream documentation for full `SealStream`/`OpenStream` API.

---

## Usage Examples

### Example 1: XChaCha20Seal — Encrypt and Decrypt (Recommended)

This is the pattern most users should follow. Bind the key at construction —
nonces are generated internally, no nonce management needed.

```typescript
import { init, XChaCha20Seal, randomBytes, utf8ToBytes, bytesToUtf8 } from 'leviathan-crypto'
import { chacha20Wasm } from 'leviathan-crypto/chacha20/embedded'

// Step 1: Initialize the chacha20 WASM module (once, at application startup)
await init({ chacha20: chacha20Wasm })

// Step 2: Generate a 256-bit encryption key
const key = randomBytes(32)

// Step 3: Create the seal instance — key is bound at construction
const seal = new XChaCha20Seal(key)

// Step 4: Encrypt — nonce is generated internally, no nonce management needed
const plaintext = utf8ToBytes('Hello, world!')
const ciphertext = seal.encrypt(plaintext)
// `ciphertext` = nonce(24) || encrypted data || tag(16)

// Step 5: Decrypt — nonce is read from the ciphertext automatically
const decrypted = seal.decrypt(ciphertext)
console.log(bytesToUtf8(decrypted))  // "Hello, world!"

// Step 6: Clean up
seal.dispose()
```

> **Need explicit nonce control?** See Example 2 (`ChaCha20Poly1305`) or use
> `XChaCha20Poly1305` directly — same API shape, 24-byte nonce passed per call.

### Example 2: ChaCha20Poly1305 — Encrypt and Decrypt

Same idea as above, but with a 12-byte nonce. Use this if you are implementing
a protocol that specifies RFC 8439 ChaCha20-Poly1305 explicitly.

Both `ChaCha20Poly1305` and `XChaCha20Poly1305` return a single `Uint8Array`
with the tag appended, and `decrypt()` expects the same combined format.
The only difference is the nonce size (12 vs 24 bytes).

> [!NOTE]
> Each `ChaCha20Poly1305` instance allows only one `encrypt()` call. A second
> call throws to prevent accidental nonce reuse. Create a new instance for each
> encryption.

```typescript
import { init, ChaCha20Poly1305, randomBytes, utf8ToBytes, bytesToUtf8 } from 'leviathan-crypto'
import { chacha20Wasm } from 'leviathan-crypto/chacha20/embedded'

await init({ chacha20: chacha20Wasm })

const key = randomBytes(32)
const aead = new ChaCha20Poly1305()

// Encrypt
const nonce = randomBytes(12)     // 12 bytes — be cautious with random generation under high volume
const plaintext = utf8ToBytes('Sensitive data')
const sealed = aead.encrypt(key, nonce, plaintext)
// sealed = ciphertext || tag(16) — store/transmit nonce and sealed together

// Decrypt (new instance — encrypt is single-use)
const aead2 = new ChaCha20Poly1305()
const decrypted = aead2.decrypt(key, nonce, sealed)
console.log(bytesToUtf8(decrypted))  // "Sensitive data"

aead.dispose()
aead2.dispose()
```

### Example 3: Detecting Tampered Ciphertext

AEAD decryption fails loudly if anyone has modified the ciphertext or
the associated data. This is a feature — it prevents you from processing
corrupted or maliciously altered data.

```typescript
import { init, XChaCha20Seal, randomBytes, utf8ToBytes } from 'leviathan-crypto'
import { chacha20Wasm } from 'leviathan-crypto/chacha20/embedded'

await init({ chacha20: chacha20Wasm })

const seal = new XChaCha20Seal(randomBytes(32))

const sealed = seal.encrypt(utf8ToBytes('Original message'))

// Simulate tampering: flip one bit in the ciphertext
const tampered = new Uint8Array(sealed)
tampered[24] ^= 0x01  // byte 24 is the first ciphertext byte (after the nonce)

try {
	const plaintext = seal.decrypt(tampered)
	// This line is never reached
	console.log(plaintext)
} catch (err) {
	console.error(err.message)
	// "ChaCha20Poly1305: authentication failed"
	// The plaintext is never returned — decryption stops immediately on failure.
}

seal.dispose()
```

### Example 4: Using Associated Data (AAD)

Associated data is metadata that you want to authenticate (prove unmodified) but
not encrypt. Common uses: user IDs, message sequence numbers, protocol version
headers, routing information.

```typescript
import { init, XChaCha20Seal, randomBytes, utf8ToBytes, bytesToUtf8 } from 'leviathan-crypto'
import { chacha20Wasm } from 'leviathan-crypto/chacha20/embedded'

await init({ chacha20: chacha20Wasm })

const seal = new XChaCha20Seal(randomBytes(32))

// The user ID travels in the clear, but decryption will fail if anyone changes it
const userId  = utf8ToBytes('user-12345')
const message = utf8ToBytes('Your account balance is $1,000,000')

const sealed = seal.encrypt(message, userId)

// Decrypt — pass the same AAD
const decrypted = seal.decrypt(sealed, userId)
console.log(bytesToUtf8(decrypted))
// "Your account balance is $1,000,000"

// If someone changes the AAD, decryption fails
const wrongUserId = utf8ToBytes('user-99999')
try {
	seal.decrypt(sealed, wrongUserId)
} catch (err) {
	console.error(err.message)
	// "ChaCha20Poly1305: authentication failed"
	// Even though the ciphertext was not modified, the AAD mismatch is detected.
}

seal.dispose()
```

### Example 5: Encrypting and Decrypting Binary Data

The API works with raw bytes — not just text. Here is an example encrypting
arbitrary binary content.

```typescript
import { init, XChaCha20Seal, randomBytes } from 'leviathan-crypto'
import { chacha20Wasm } from 'leviathan-crypto/chacha20/embedded'

await init({ chacha20: chacha20Wasm })

const seal = new XChaCha20Seal(randomBytes(32))

// Encrypt binary data (e.g., an image thumbnail, a protobuf, a file chunk)
const binaryData = new Uint8Array([0x89, 0x50, 0x4e, 0x47, /* ...more bytes... */])
const sealed = seal.encrypt(binaryData)

// Decrypt
const recovered = seal.decrypt(sealed)
// `recovered` is byte-identical to `binaryData`

seal.dispose()
```

### Example 6: Raw ChaCha20 Stream Cipher (Advanced)

Use this only if you are building a custom protocol and will add your own
authentication layer. For almost all use cases, use `XChaCha20Seal` instead.

```typescript
import { init, ChaCha20, randomBytes } from 'leviathan-crypto'
import { chacha20Wasm } from 'leviathan-crypto/chacha20/embedded'

await init({ chacha20: chacha20Wasm })

const key = randomBytes(32)
const nonce = randomBytes(12)
const cipher = new ChaCha20()

// Encrypt
cipher.beginEncrypt(key, nonce)
const ct1 = cipher.encryptChunk(new Uint8Array([1, 2, 3, 4]))
const ct2 = cipher.encryptChunk(new Uint8Array([5, 6, 7, 8]))

// Decrypt — uses the same key and nonce
cipher.beginDecrypt(key, nonce)
const pt1 = cipher.decryptChunk(ct1)
const pt2 = cipher.decryptChunk(ct2)
// pt1 = [1, 2, 3, 4], pt2 = [5, 6, 7, 8]

// WARNING: Without authentication, an attacker can flip bits in ciphertext
// and the corresponding plaintext bits will flip with no error.
// Pair with HMAC (Encrypt-then-MAC) or use XChaCha20Poly1305 instead.

cipher.dispose()
```

## Error Conditions

| Condition | Error Type | Message |
|-----------|-----------|---------|
| `init({ chacha20: ... })` not called before constructing a class | `Error` | `leviathan-crypto: call init({ chacha20: ... }) before using this class` |
| Key is not 32 bytes | `RangeError` | `ChaCha20 key must be 32 bytes (got N)` / `key must be 32 bytes (got N)` / `Poly1305 key must be 32 bytes (got N)` |
| `ChaCha20` nonce is not 12 bytes | `RangeError` | `ChaCha20 nonce must be 12 bytes (got N)` |
| `ChaCha20Poly1305` nonce is not 12 bytes | `RangeError` | `nonce must be 12 bytes (got N)` |
| `XChaCha20Poly1305` nonce is not 24 bytes | `RangeError` | `XChaCha20 nonce must be 24 bytes (got N)` |
| `ChaCha20Poly1305` ciphertext shorter than 16 bytes | `RangeError` | `ciphertext too short — must include 16-byte tag (got N)` |
| `XChaCha20Poly1305` ciphertext shorter than 16 bytes | `RangeError` | `ciphertext too short — must include 16-byte tag (got N)` |
| `ChaCha20Poly1305.encrypt()` called a second time | `Error` | Single-use encrypt guard — create a new instance for each encryption |
| Chunk or plaintext exceeds WASM buffer size | `RangeError` | `plaintext exceeds N bytes — split into smaller chunks` / `chunk exceeds maximum size of N bytes — split into smaller chunks` |
| Authentication tag does not match on decrypt | `Error` | `ChaCha20Poly1305: authentication failed` |
| Empty plaintext | — | Allowed. Encrypting zero bytes produces just a 16-byte tag (AEAD) or zero bytes (raw ChaCha20). |

> ## Cross-References
>
> - [index](./README.md) — Project Documentation index
> - [asm_chacha](./asm_chacha.md) — WASM (AssemblyScript) implementation details for the chacha20 module
> - [serpent](./serpent.md) — alternative: Serpent block cipher modes (CBC, CTR — unauthenticated, needs HMAC pairing)
> - [sha2](./sha2.md) — SHA-2 hashes and HMAC — needed for Encrypt-then-MAC if using Serpent or raw ChaCha20
> - [types](./types.md) — `AEAD` and `Streamcipher` interfaces implemented by ChaCha20 classes
> - [chacha_audit.md](./chacha_audit.md) — XChaCha20-Poly1305 implementation audit
