# ChaCha20, Poly1305, and AEAD TypeScript API

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
messages. **For most users, XChaCha20Poly1305 is the recommended choice.** It gives
you encryption and authentication in one call, with a nonce size that eliminates
the most common footgun (accidental nonce reuse).

## Security Notes

> [!IMPORTANT]
> Read this section before writing any code. These are not theoretical concerns —
> they are the mistakes that cause real-world breaches.

- **Use `XChaCha20Poly1305` unless you have a specific reason not to.** It is the
  safest default: authenticated encryption with a nonce large enough for random
  generation. If you are unsure which class to pick, pick this one.

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

### `chacha20Init(mode?, opts?)`

Initializes only the chacha20 WASM binary. Equivalent to calling the
root `init(['chacha20'], mode, opts)` but without pulling the other three
modules into the bundle.

**Signature:**

```typescript
async function chacha20Init(mode?: Mode, opts?: InitOpts): Promise<void>
```

**Usage:**

```typescript
import { chacha20Init, XChaCha20Poly1305 } from 'leviathan-crypto/chacha20'

await chacha20Init()
const aead = new XChaCha20Poly1305()
```

---

## API Reference

All classes require calling `await init(['chacha20'])` or the subpath `chacha20Init()`
before construction. If you construct a class before initialization, it throws:
```
Error: leviathan-crypto: call init(['chacha20']) before using this class
```

---

### `ChaCha20`

Raw ChaCha20 stream cipher. **No authentication** — use `XChaCha20Poly1305` instead
unless you are building a custom protocol and understand the risks.

#### Constructor

```typescript
new ChaCha20()
```

Throws if `init(['chacha20'])` has not been called.

#### `beginEncrypt(key: Uint8Array, nonce: Uint8Array): void`

Prepares the cipher for encryption with the given key and nonce.

| Parameter | Type | Description |
|-----------|------|-------------|
| `key` | `Uint8Array` | 32 bytes (256 bits) |
| `nonce` | `Uint8Array` | 12 bytes (96 bits) |

**Throws** `RangeError` if `key` is not 32 bytes or `nonce` is not 12 bytes.

#### `encryptChunk(chunk: Uint8Array): Uint8Array`

Encrypts a chunk of plaintext. Call repeatedly for streaming encryption. Returns
a new `Uint8Array` containing the ciphertext (same length as input).

| Parameter | Type | Description |
|-----------|------|-------------|
| `chunk` | `Uint8Array` | Plaintext bytes (up to the module's chunk size limit) |

**Throws** `RangeError` if the chunk exceeds the maximum chunk size.

#### `beginDecrypt(key: Uint8Array, nonce: Uint8Array): void`

Prepares the cipher for decryption. Identical to `beginEncrypt` — ChaCha20 is
symmetric (encryption and decryption are the same XOR operation).

| Parameter | Type | Description |
|-----------|------|-------------|
| `key` | `Uint8Array` | 32 bytes (256 bits) |
| `nonce` | `Uint8Array` | 12 bytes (96 bits) |

**Throws** `RangeError` if `key` is not 32 bytes or `nonce` is not 12 bytes.

#### `decryptChunk(chunk: Uint8Array): Uint8Array`

Decrypts a chunk of ciphertext. Returns a new `Uint8Array` containing the
plaintext (same length as input).

| Parameter | Type | Description |
|-----------|------|-------------|
| `chunk` | `Uint8Array` | Ciphertext bytes |

**Throws** `RangeError` if the chunk exceeds the maximum chunk size.

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

Throws if `init(['chacha20'])` has not been called.

#### `mac(key: Uint8Array, msg: Uint8Array): Uint8Array`

Computes a 16-byte Poly1305 authentication tag over the given message.

| Parameter | Type | Description |
|-----------|------|-------------|
| `key` | `Uint8Array` | 32 bytes — must be unique per message |
| `msg` | `Uint8Array` | The message to authenticate (any length) |

**Returns** `Uint8Array` — a 16-byte authentication tag.

**Throws** `RangeError` if `key` is not 32 bytes.

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

Throws if `init(['chacha20'])` has not been called.

#### `encrypt(key, nonce, plaintext, aad?): { ciphertext: Uint8Array; tag: Uint8Array }`

Encrypts plaintext and produces a 16-byte authentication tag.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `key` | `Uint8Array` | | 32 bytes (256-bit key) |
| `nonce` | `Uint8Array` | | 12 bytes (96-bit nonce) |
| `plaintext` | `Uint8Array` | | Data to encrypt (up to the module's chunk size limit) |
| `aad` | `Uint8Array` | `new Uint8Array(0)` | Associated data — authenticated but not encrypted |

**Returns** `{ ciphertext: Uint8Array; tag: Uint8Array }` — the ciphertext (same
length as plaintext) and a 16-byte authentication tag. You need both to decrypt.

**Throws:**
- `RangeError` if `key` is not 32 bytes
- `RangeError` if `nonce` is not 12 bytes
- `RangeError` if `plaintext` exceeds the maximum chunk size

#### `decrypt(key, nonce, ciphertext, tag, aad?): Uint8Array`

Verifies the authentication tag and decrypts the ciphertext. If authentication
fails, an error is thrown and no plaintext is returned.

Tag comparison uses a constant-time XOR-accumulate pattern — no timing side
channel leaks whether the tag was "close" to correct.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `key` | `Uint8Array` | | 32 bytes (same key used for encryption) |
| `nonce` | `Uint8Array` | | 12 bytes (same nonce used for encryption) |
| `ciphertext` | `Uint8Array` | | Encrypted data |
| `tag` | `Uint8Array` | | 16-byte authentication tag from `encrypt()` |
| `aad` | `Uint8Array` | `new Uint8Array(0)` | Associated data (must match what was passed to `encrypt()`) |

**Returns** `Uint8Array` — the decrypted plaintext.

**Throws:**
- `RangeError` if `key` is not 32 bytes
- `RangeError` if `nonce` is not 12 bytes
- `RangeError` if `tag` is not 16 bytes
- `RangeError` if `ciphertext` exceeds the maximum chunk size
- `Error('ChaCha20Poly1305: authentication failed')` if the tag does not match

#### `dispose(): void`

Wipes all key material and intermediate state from WASM memory.

---

### `XChaCha20Poly1305`

XChaCha20-Poly1305 AEAD (draft-irtf-cfrg-xchacha). **This is the recommended
authenticated encryption class for most use cases.**

It uses a 24-byte (192-bit) nonce, which is large enough that randomly generated
nonces will never collide in practice. Internally, it derives a subkey via
HChaCha20 and delegates to `ChaCha20Poly1305`.

Unlike `ChaCha20Poly1305`, the `encrypt()` method returns a single `Uint8Array`
with the tag appended to the ciphertext. The `decrypt()` method expects this
combined format and splits it internally.

#### Constructor

```typescript
new XChaCha20Poly1305()
```

Throws if `init(['chacha20'])` has not been called.

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

#### `dispose(): void`

Wipes all key material and intermediate state from WASM memory.

---

## Parallel pool — `XChaCha20Poly1305Pool`

For high-throughput workloads where multiple XChaCha20-Poly1305 operations should
run concurrently, `XChaCha20Poly1305Pool` dispatches work across a configurable
number of Web Workers, each holding an isolated `chacha.wasm` instance in its own
linear memory. This removes the single-threaded bottleneck of a shared WASM
instance and allows encryption and decryption operations to proceed in parallel.
The pool requires `init(['chacha20'])` to be called before construction and is
created via the static factory `XChaCha20Poly1305Pool.create(opts?)` — see
[chacha20_pool.md](./chacha20_pool.md) for the full API reference, pool sizing
guidance, and lifecycle docs.

---

## Usage Examples

### Example 1: XChaCha20Poly1305 — Encrypt and Decrypt (Recommended)

This is the pattern most users should follow. Generate a random 24-byte nonce for
each message — no counter management, no collision risk.

```typescript
import { init, XChaCha20Poly1305, randomBytes, utf8ToBytes, bytesToUtf8 } from 'leviathan-crypto'

// Step 1: Initialize the chacha20 WASM module (once, at application startup)
await init(['chacha20'])

// Step 2: Generate a 256-bit encryption key
// In a real application, this comes from a key derivation function or key exchange.
const key = randomBytes(32)

// Step 3: Create the AEAD instance
const aead = new XChaCha20Poly1305()

// Step 4: Encrypt
const nonce = randomBytes(24)     // Safe to generate randomly — 24 bytes means no collision risk
const plaintext = utf8ToBytes('Hello, world!')
const sealed = aead.encrypt(key, nonce, plaintext)
// `sealed` contains the ciphertext + 16-byte authentication tag

// Step 5: Decrypt
// You need the same key and nonce to decrypt.
// Store or transmit the nonce alongside the ciphertext — the nonce is not secret.
const decrypted = aead.decrypt(key, nonce, sealed)
console.log(bytesToUtf8(decrypted))  // "Hello, world!"

// Step 6: Clean up — wipe key material from WASM memory
aead.dispose()
```

### Example 2: ChaCha20Poly1305 — Encrypt and Decrypt

Same idea as above, but with a 12-byte nonce. Use this if you are implementing
a protocol that specifies RFC 8439 ChaCha20-Poly1305 explicitly.

Note the differences from `XChaCha20Poly1305`:
- The nonce is 12 bytes, not 24
- `encrypt()` returns `{ ciphertext, tag }` as separate fields
- `decrypt()` takes the tag as a separate parameter

```typescript
import { init, ChaCha20Poly1305, randomBytes, utf8ToBytes, bytesToUtf8 } from 'leviathan-crypto'

await init(['chacha20'])

const key = randomBytes(32)
const aead = new ChaCha20Poly1305()

// Encrypt
const nonce = randomBytes(12)     // 12 bytes — be cautious with random generation under high volume
const plaintext = utf8ToBytes('Sensitive data')
const { ciphertext, tag } = aead.encrypt(key, nonce, plaintext)
// You must store/transmit nonce, ciphertext, AND tag — all three are needed to decrypt

// Decrypt
const decrypted = aead.decrypt(key, nonce, ciphertext, tag)
console.log(bytesToUtf8(decrypted))  // "Sensitive data"

aead.dispose()
```

### Example 3: Detecting Tampered Ciphertext

AEAD decryption fails loudly if anyone has modified the ciphertext, the tag, or
the associated data. This is a feature — it prevents you from processing corrupted
or maliciously altered data.

```typescript
import { init, XChaCha20Poly1305, randomBytes, utf8ToBytes } from 'leviathan-crypto'

await init(['chacha20'])

const key = randomBytes(32)
const nonce = randomBytes(24)
const aead = new XChaCha20Poly1305()

const sealed = aead.encrypt(key, nonce, utf8ToBytes('Original message'))

// Simulate tampering: flip one bit in the ciphertext
const tampered = new Uint8Array(sealed)
tampered[0] ^= 0x01

try {
	const plaintext = aead.decrypt(key, nonce, tampered)
	// This line is never reached
	console.log(plaintext)
} catch (err) {
	console.error(err.message)
	// "ChaCha20Poly1305: authentication failed"
	// The plaintext is never returned — decryption stops immediately on failure.
}

aead.dispose()
```

### Example 4: Using Associated Data (AAD)

Associated data is metadata that you want to authenticate (prove unmodified) but
not encrypt. Common uses: user IDs, message sequence numbers, protocol version
headers, routing information.

```typescript
import { init, XChaCha20Poly1305, randomBytes, utf8ToBytes, bytesToUtf8 } from 'leviathan-crypto'

await init(['chacha20'])

const key = randomBytes(32)
const nonce = randomBytes(24)
const aead = new XChaCha20Poly1305()

// The user ID travels in the clear, but decryption will fail if anyone changes it
const userId = utf8ToBytes('user-12345')
const message = utf8ToBytes('Your account balance is $1,000,000')

const sealed = aead.encrypt(key, nonce, message, userId)

// Decrypt — pass the same AAD
const decrypted = aead.decrypt(key, nonce, sealed, userId)
console.log(bytesToUtf8(decrypted))
// "Your account balance is $1,000,000"

// If someone changes the AAD, decryption fails
const wrongUserId = utf8ToBytes('user-99999')
try {
	aead.decrypt(key, nonce, sealed, wrongUserId)
} catch (err) {
	console.error(err.message)
	// "ChaCha20Poly1305: authentication failed"
	// Even though the ciphertext was not modified, the AAD mismatch is detected.
}

aead.dispose()
```

### Example 5: Encrypting and Decrypting Binary Data

The API works with raw bytes — not just text. Here is an example encrypting
arbitrary binary content.

```typescript
import { init, XChaCha20Poly1305, randomBytes } from 'leviathan-crypto'

await init(['chacha20'])

const key = randomBytes(32)
const nonce = randomBytes(24)
const aead = new XChaCha20Poly1305()

// Encrypt binary data (e.g., an image thumbnail, a protobuf, a file chunk)
const binaryData = new Uint8Array([0x89, 0x50, 0x4e, 0x47, /* ...more bytes... */])
const sealed = aead.encrypt(key, nonce, binaryData)

// Decrypt
const recovered = aead.decrypt(key, nonce, sealed)
// `recovered` is byte-identical to `binaryData`

aead.dispose()
```

### Example 6: Raw ChaCha20 Stream Cipher (Advanced)

Use this only if you are building a custom protocol and will add your own
authentication layer. For almost all use cases, use `XChaCha20Poly1305` instead.

```typescript
import { init, ChaCha20, randomBytes } from 'leviathan-crypto'

await init(['chacha20'])

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
| `init(['chacha20'])` not called before constructing a class | `Error` | `leviathan-crypto: call init(['chacha20']) before using this class` |
| Key is not 32 bytes | `RangeError` | `ChaCha20 key must be 32 bytes (got N)` / `key must be 32 bytes (got N)` / `Poly1305 key must be 32 bytes (got N)` |
| `ChaCha20` nonce is not 12 bytes | `RangeError` | `ChaCha20 nonce must be 12 bytes (got N)` |
| `ChaCha20Poly1305` nonce is not 12 bytes | `RangeError` | `nonce must be 12 bytes (got N)` |
| `XChaCha20Poly1305` nonce is not 24 bytes | `RangeError` | `XChaCha20 nonce must be 24 bytes (got N)` |
| `ChaCha20Poly1305` tag is not 16 bytes | `RangeError` | `tag must be 16 bytes (got N)` |
| `XChaCha20Poly1305` ciphertext shorter than 16 bytes | `RangeError` | `ciphertext too short — must include 16-byte tag (got N)` |
| Chunk or plaintext exceeds WASM buffer size | `RangeError` | `plaintext exceeds N bytes — split into smaller chunks` / `chunk exceeds maximum size of N bytes — split into smaller chunks` |
| Authentication tag does not match on decrypt | `Error` | `ChaCha20Poly1305: authentication failed` |
| Empty plaintext | — | Allowed. Encrypting zero bytes produces just a 16-byte tag (AEAD) or zero bytes (raw ChaCha20). |

## Cross-References

- [README.md](./README.md)
- [asm_chacha.md](./asm_chacha.md) — WASM (AssemblyScript) implementation details for the chacha20 module
- [serpent.md](./serpent.md) — Alternative: Serpent block cipher modes (CBC, CTR — unauthenticated, needs HMAC pairing)
- [sha2.md](./sha2.md) — SHA-2 hashes and HMAC — needed for Encrypt-then-MAC if using Serpent or raw ChaCha20
