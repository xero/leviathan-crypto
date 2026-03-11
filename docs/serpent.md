# Serpent-256 block cipher TypeScript API

> [!NOTE]
> Encrypt and decrypt data using the Serpent block cipher in three modes:
> raw block operations, CTR streaming, and CBC with automatic padding.

## Overview

Serpent is the flagship encryption algorithm in leviathan-crypto. It is a
**block cipher** -- a cryptographic function that takes a fixed-size block of data
(16 bytes) and a secret key, and transforms the block into ciphertext that cannot
be read without the key. Think of it like a lock: anyone can see the locked box,
but only someone with the key can open it and read the contents.

Because real-world data is rarely exactly 16 bytes, leviathan-crypto provides
three classes built on Serpent. `Serpent` performs raw 16-byte block operations --
useful as a building block but not for encrypting messages directly. `SerpentCtr`
uses Counter (CTR) mode to encrypt data of any length as a stream. `SerpentCbc`
uses Cipher Block Chaining (CBC) mode with automatic PKCS7 padding, which also
handles data of any length.

Serpent supports three key sizes: 128-bit (16 bytes), 192-bit (24 bytes), and
256-bit (32 bytes). **Always use 256-bit keys** unless you have a specific,
well-understood reason to use a shorter key. A 256-bit key provides the maximum
security margin with no practical performance difference.

Why Serpent instead of AES? Serpent was a finalist in the AES competition and
placed second -- not because of any weakness, but because AES (Rijndael) was
slightly faster. Serpent uses 32 rounds of encryption compared to AES's 14, giving
it a significantly larger security margin. Its bitslice design also provides
natural resistance to timing side-channel attacks, making it a strong choice when
security margin matters more than raw speed.

---

## Security Notes

Read this section carefully before using any Serpent class. These are not
theoretical concerns -- ignoring them can make your encryption useless.

### Always use 256-bit keys

Unless you have a specific reason to use a shorter key, pass a 32-byte key to
every Serpent operation. Shorter keys provide less security margin and there is no
meaningful performance benefit to using them.

### SerpentCbc and SerpentCtr are unauthenticated

This is the most important thing to understand. **Unauthenticated** means that
while an attacker cannot read your encrypted data, they *can* modify it without
you knowing. Imagine sending a locked letter: the recipient can open it and read
the original contents, but if someone swapped the letter inside the locked box
along the way, neither of you would know.

In practice, this means an attacker could flip bits in your ciphertext and the
decryption would still succeed -- it would just produce wrong plaintext. This is
called a **ciphertext malleability** attack.

**For most use cases, use `XChaCha20Poly1305` instead.** It provides both
encryption (confidentiality) and authentication (tamper detection) in a single
operation. See [chacha20.md](./chacha20.md).

If you must use Serpent modes, pair them with `HMAC_SHA256` in the
**Encrypt-then-MAC** pattern: encrypt first, then compute an HMAC over the
ciphertext. On the receiving end, verify the HMAC *before* attempting decryption.
See Example 4 below for a complete implementation.

### Never reuse a nonce or IV with the same key

- **CTR mode**: Reusing a nonce with the same key is catastrophic. It produces the
  same keystream, which means an attacker can XOR two ciphertexts together and
  recover both plaintexts. Always generate a fresh random nonce for each message.
- **CBC mode**: The IV (initialization vector) must be random and unpredictable for
  each encryption. A predictable IV enables chosen-plaintext attacks.

Use `randomBytes(16)` to generate nonces and IVs.

### Call dispose() when done

Every Serpent class holds key material in WebAssembly memory. When you are finished
with an instance, call `dispose()` to zero out all key material, intermediate
state, and buffers. Failing to call `dispose()` means sensitive data may persist
in memory longer than necessary.

---

## Module Init

Each module subpath exports its own `init()` for consumers who want
tree-shakeable imports.

### `init(mode?, opts?)`

Initializes only the serpent WASM binary. Equivalent to calling the
root `init(['serpent'], mode, opts)` but without pulling the other three
modules into the bundle.

**Signature:**

```typescript
async function init(mode?: Mode, opts?: InitOpts): Promise<void>
```

**Usage:**

```typescript
import { init, Serpent } from 'leviathan-crypto/serpent'

await init()
const cipher = new Serpent()
```

---

## API Reference

All three classes require `init(['serpent'])` or the subpath `init()` to be
called before construction.
Attempting to construct any Serpent class before initialization throws an error:

```
leviathan-crypto: call init(['serpent']) before using this class
```

### Serpent

Raw Serpent block encryption and decryption. Operates on exactly 16-byte blocks.
This class is a low-level building block -- most users should use `SerpentCtr` or
`SerpentCbc` instead.

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

Creates a new Serpent instance. Throws if `init(['serpent'])` has not been called.

#### `loadKey(key: Uint8Array): void`

Loads and expands a key for subsequent block operations. Must be called before
`encryptBlock()` or `decryptBlock()`.

- **key** -- 16, 24, or 32 bytes. Throws `RangeError` if the length is invalid.

#### `encryptBlock(plaintext: Uint8Array): Uint8Array`

Encrypts a single 16-byte block and returns the 16-byte ciphertext.

- **plaintext** -- exactly 16 bytes. Throws `RangeError` if the length is not 16.

#### `decryptBlock(ciphertext: Uint8Array): Uint8Array`

Decrypts a single 16-byte block and returns the 16-byte plaintext.

- **ciphertext** -- exactly 16 bytes. Throws `RangeError` if the length is not 16.

#### `dispose(): void`

Wipes all key material and intermediate state from WASM memory. Always call this
when you are done with the instance.

---

### SerpentCtr

Serpent in Counter (CTR) mode. Encrypts and decrypts data of any length as a
stream of chunks.

> [!WARNING]
> CTR mode is unauthenticated. An attacker can modify ciphertext
> without detection. Always pair with HMAC-SHA256 (Encrypt-then-MAC) or use
> `XChaCha20Poly1305` instead.

```typescript
class SerpentCtr {
	constructor()
	beginEncrypt(key: Uint8Array, nonce: Uint8Array): void
	encryptChunk(chunk: Uint8Array): Uint8Array
	beginDecrypt(key: Uint8Array, nonce: Uint8Array): void
	decryptChunk(chunk: Uint8Array): Uint8Array
	dispose(): void
}
```

#### `constructor()`

Creates a new SerpentCtr instance. Throws if `init(['serpent'])` has not been called.

#### `beginEncrypt(key: Uint8Array, nonce: Uint8Array): void`

Initializes the CTR state for encryption. Loads the key, sets the nonce, and
resets the internal counter to zero.

- **key** -- 16, 24, or 32 bytes. Throws `RangeError` if the length is invalid.
- **nonce** -- exactly 16 bytes. Throws `RangeError` if the length is not 16.

#### `encryptChunk(chunk: Uint8Array): Uint8Array`

Encrypts a chunk of plaintext and returns the same-length ciphertext. Call this
one or more times after `beginEncrypt()`. The internal counter advances
automatically.

- **chunk** -- any length up to the module's internal chunk buffer size. Throws
  `RangeError` if the chunk exceeds the maximum size.

#### `beginDecrypt(key: Uint8Array, nonce: Uint8Array): void`

Initializes the CTR state for decryption. Functionally identical to
`beginEncrypt()` -- CTR mode uses the same operation in both directions.

- **key** -- 16, 24, or 32 bytes. Throws `RangeError` if the length is invalid.
- **nonce** -- exactly 16 bytes. Throws `RangeError` if the length is not 16.

#### `decryptChunk(chunk: Uint8Array): Uint8Array`

Decrypts a chunk of ciphertext and returns the same-length plaintext.
Functionally identical to `encryptChunk()`.

- **chunk** -- any length up to the module's internal chunk buffer size. Throws
  `RangeError` if the chunk exceeds the maximum size.

#### `dispose(): void`

Wipes all key material and intermediate state from WASM memory.

---

### SerpentCbc

Serpent in Cipher Block Chaining (CBC) mode with automatic PKCS7 padding.
Encrypts and decrypts entire messages in a single call.

> [!WARNING]
> CBC mode is unauthenticated. Always authenticate the output with
> HMAC-SHA256 (Encrypt-then-MAC) or use `XChaCha20Poly1305` instead.

```typescript
class SerpentCbc {
	constructor()
	encrypt(key: Uint8Array, iv: Uint8Array, plaintext: Uint8Array): Uint8Array
	decrypt(key: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array): Uint8Array
	dispose(): void
}
```

#### `constructor()`

Creates a new SerpentCbc instance. Throws if `init(['serpent'])` has not been called.

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

#### `dispose(): void`

Wipes all key material and intermediate state from WASM memory.

---

## Usage Examples

### Example 1: Raw block encrypt/decrypt

Use the `Serpent` class for single 16-byte block operations. This is the lowest
level API -- most users should skip to Example 2 or 3.

```typescript
import { init, Serpent } from 'leviathan-crypto';

// Initialize the Serpent WASM module (required once before any Serpent usage)
await init(['serpent']);

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

### Example 2: CTR mode streaming encryption

Use `SerpentCtr` to encrypt data of any length. CTR mode produces ciphertext
that is the same length as the plaintext -- no padding overhead.

```typescript
import { init, SerpentCtr, randomBytes } from 'leviathan-crypto';

await init(['serpent']);

const key   = randomBytes(32); // 256-bit key
const nonce = randomBytes(16); // 16-byte nonce -- NEVER reuse with the same key

const ctr = new SerpentCtr();

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
> ciphertext without detection. See Example 4 for how to add authentication, or
> use `XChaCha20Poly1305` instead.

### Example 3: CBC mode encrypt/decrypt

Use `SerpentCbc` for message-level encryption with automatic PKCS7 padding.

```typescript
import { init, SerpentCbc, randomBytes } from 'leviathan-crypto';

await init(['serpent']);

const key = randomBytes(32); // 256-bit key
const iv  = randomBytes(16); // Random IV -- must be unique per message

const cbc = new SerpentCbc();

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
> CBC mode is unauthenticated. See the next example for the secure
> Encrypt-then-MAC pattern.

### Example 4: Encrypt-then-MAC (SerpentCbc + HMAC_SHA256)

This is the **recommended pattern** when you need Serpent encryption with tamper
detection. The idea is simple: encrypt the data, then compute a MAC (message
authentication code) over the ciphertext. The recipient verifies the MAC before
attempting decryption. If the ciphertext was tampered with, the MAC check fails
and you reject the message without ever decrypting it.

```typescript
import {
	init, SerpentCbc, HMAC_SHA256,
	randomBytes, constantTimeEqual, concat,
} from 'leviathan-crypto';

// Initialize both the Serpent and SHA-2 WASM modules
await init(['serpent', 'sha2']);

// Use separate keys for encryption and MAC -- never reuse the same key for both
const encKey  = randomBytes(32); // 256-bit encryption key
const macKey  = randomBytes(32); // 256-bit MAC key
const iv      = randomBytes(16); // Random IV

// ── Encrypt and authenticate ────────────────────────────────────────

const cbc  = new SerpentCbc();
const hmac = new HMAC_SHA256();

const plaintext  = new TextEncoder().encode('Authenticated secret message.');
const ciphertext = cbc.encrypt(encKey, iv, plaintext);

// MAC covers the IV and ciphertext together.
// This prevents an attacker from swapping IVs between messages.
const macInput = concat(iv, ciphertext);
const tag      = hmac.hash(macKey, macInput);

// Send or store: iv + ciphertext + tag

// ── Verify and decrypt ──────────────────────────────────────────────

// On the receiving end, recompute the MAC and verify it BEFORE decrypting
const receivedMacInput = concat(iv, ciphertext);
const expectedTag      = hmac.hash(macKey, receivedMacInput);

// Use constant-time comparison to prevent timing attacks
if (!constantTimeEqual(tag, expectedTag)) {
	throw new Error('Authentication failed -- ciphertext was tampered with');
}

// MAC verified -- safe to decrypt
const decrypted = cbc.decrypt(encKey, iv, ciphertext);
console.log(new TextDecoder().decode(decrypted));
// "Authenticated secret message."

// Wipe key material
cbc.dispose();
hmac.dispose();
```

**Key points about Encrypt-then-MAC:**

- Use **two separate keys**: one for encryption, one for the MAC. Never use the
  same key for both operations.
- Always MAC the **IV and ciphertext together**. If you MAC only the ciphertext,
  an attacker could swap the IV and produce a different decryption.
- Always verify the MAC **before** decrypting. If the MAC does not match, reject
  the message immediately. Never decrypt unauthenticated ciphertext.
- Use `constantTimeEqual()` for the tag comparison. A regular `===` or byte-by-byte
  comparison leaks timing information that an attacker can exploit to forge MACs.

---

## Error Conditions

| Condition | Error type | Message |
|-----------|-----------|---------|
| `init(['serpent'])` not called before constructing a class | `Error` | `leviathan-crypto: call init(['serpent']) before using this class` |
| Key is not 16, 24, or 32 bytes | `RangeError` | `key must be 16, 24, or 32 bytes (got N)` |
| Block is not 16 bytes (`Serpent`) | `RangeError` | `block must be 16 bytes (got N)` |
| Nonce is not 16 bytes (`SerpentCtr`) | `RangeError` | `nonce must be 16 bytes (got N)` |
| Chunk exceeds buffer size (`SerpentCtr`) | `RangeError` | `chunk exceeds maximum size of N bytes -- split into smaller chunks` |
| IV is not 16 bytes (`SerpentCbc`) | `RangeError` | `CBC IV must be 16 bytes (got N)` |
| Ciphertext length is zero or not a multiple of 16 (`SerpentCbc.decrypt`) | `RangeError` | `ciphertext length must be a non-zero multiple of 16` |
| Invalid PKCS7 padding on decrypt (`SerpentCbc.decrypt`) | `RangeError` | `invalid PKCS7 padding` |

---

## Cross-References

- [README.md](./README.md)
- [architecture.md](./architecture.md)
- [asm_serpent.md](./asm_serpent.md): WASM implementation details and buffer layout
- [serpent_reference.md](./serpent_reference.md): Algorithm specification and design rationale
- [serpent_audit.md](./serpent_audit.md): Security audit findings
- [chacha20.md](./chacha20.md): XChaCha20Poly1305: authenticated encryption (recommended for most use cases)
- [sha2.md](./sha2.md): HMAC-SHA256 for Encrypt-then-MAC pattern
