# SHA-2 hash functions and HMAC TypeScript API

> [!NOTE]
> Cryptographic hashing and message authentication using SHA-256, SHA-384,
> SHA-512, HMAC-SHA256, HMAC-SHA384, and HMAC-SHA512.
>
> See [SHA-2 implementation audit](./sha2_audit.md), [HMAC audit](./hmac_audit.md), and [HKDF audit](./hkdf_audit.md) for algorithm correctness verifications.

## Overview

SHA-2 is a family of cryptographic hash functions standardized in
[FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final).
A hash function takes an input of any size -- a password, a file, a single
byte -- and produces a fixed-size output called a **digest** (sometimes called
a "fingerprint" or "hash"). Even the smallest change to the input produces a
completely different digest. This makes hash functions useful for verifying that
data has not been tampered with.

leviathan-crypto provides three SHA-2 variants:

- **SHA-256** -- 32-byte (256-bit) digest. The most widely used variant. Use
  this unless you have a specific reason to choose another.
- **SHA-512** -- 64-byte (512-bit) digest. Higher security margin. Faster than
  SHA-256 on 64-bit platforms.
- **SHA-384** -- 48-byte (384-bit) digest. A truncated variant of SHA-512.
  Useful when you need a digest longer than 256 bits but shorter than 512 bits,
  or when a protocol specifies it (e.g. TLS cipher suites).

**HMAC** (Hash-based Message Authentication Code, [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104))
combines a secret key with a hash function to produce a **tag** that proves both
the integrity and the authenticity of a message. Anyone can compute a plain SHA-256
hash of a message -- but only someone who holds the secret key can compute the
correct HMAC tag. This means the recipient can verify that the message was sent by
someone who knows the key, and that it was not modified in transit.

leviathan-crypto provides three HMAC variants corresponding to each hash:

- **HMAC_SHA256** -- 32-byte tag, using SHA-256
- **HMAC_SHA512** -- 64-byte tag, using SHA-512
- **HMAC_SHA384** -- 48-byte tag, using SHA-384

All computation runs in WebAssembly. The TypeScript classes handle input
validation and the JS/WASM boundary -- they never implement cryptographic
algorithms directly.

---

## Security Notes

> [!IMPORTANT]
> Read these before using the API. Misusing hash functions is one of the most
> common sources of security vulnerabilities.

### Hashing is NOT encryption

A hash is a one-way function. You **cannot** recover the original input from a
hash digest. If you need to protect data so that it can be read later, you need
encryption (see [serpent.md](./serpent.md) or use `XChaCha20Poly1305`).

### Do NOT use plain SHA-2 for passwords

SHA-2 is extremely fast by design. An attacker with a GPU can compute billions
of SHA-256 hashes per second, making brute-force attacks on passwords trivial.
For password hashing, use a memory-hardened function like **Argon2id**. See
[argon2id.md](./argon2id.md) for usage patterns including passphrase-based
encryption with leviathan primitives.

### SHA-2 is vulnerable to length extension attacks

Never construct a MAC by concatenating a secret and a message and hashing them:

```typescript
// DANGEROUS -- DO NOT DO THIS
const bad = sha256.hash(concat(secret, message))
```

An attacker who sees `SHA256(secret || message)` can compute
`SHA256(secret || message || padding || attacker_data)` without knowing the
secret. This is called a **length extension attack**.

**Always use HMAC** when you need to authenticate a message with a secret key.
HMAC is specifically designed to be immune to this attack.

### HMAC key length

HMAC keys should be **at least as long as the hash output**:

| HMAC variant  | Minimum recommended key length |
|---------------|-------------------------------|
| HMAC_SHA256   | 32 bytes (256 bits)           |
| HMAC_SHA384   | 48 bytes (384 bits)           |
| HMAC_SHA512   | 64 bytes (512 bits)           |

Keys shorter than this are technically valid (they will be zero-padded
internally) but provide less security than the hash function offers. Keys
longer than the hash block size (64 bytes for SHA-256, 128 bytes for
SHA-384/SHA-512) are pre-hashed automatically per RFC 2104 section 3 -- this is
handled for you, but there is no benefit to using very long keys.

### Always use constant-time comparison for HMAC verification

When verifying an HMAC tag, **never** use `===` or any other comparison that
can return early on the first mismatched byte. An attacker can measure how long
the comparison takes and use that information to forge a valid tag one byte at a
time (this is called a **timing attack**).

Use `constantTimeEqual()` from leviathan-crypto instead. It always compares
every byte regardless of where the first difference is.

### Call dispose() when you are done

`dispose()` calls `wipeBuffers()` in the WASM module, which zeroes out all
internal buffers including hash state and key material. This prevents sensitive
data from lingering in memory. Always call `dispose()` when you are finished
with a hash or HMAC instance.

---

## Module Init

Each module subpath exports its own init function for consumers who want
tree-shakeable imports.

### `sha2Init(source)`

Initializes only the sha2 WASM binary. Equivalent to calling the
root `init({ sha2: source })` but without pulling the other three
modules into the bundle.

**Signature:**

```typescript
async function sha2Init(source: WasmSource): Promise<void>
```

**Usage:**

```typescript
import { sha2Init, SHA256 } from 'leviathan-crypto/sha2'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await sha2Init(sha2Wasm)
const sha = new SHA256()
```

---

## API Reference

All classes require `init({ sha2: sha2Wasm })` or the subpath `sha2Init(sha2Wasm)` to be called first.
Constructing any SHA-2 class before initialization throws an error.

### SHA256

Computes a SHA-256 hash (32-byte digest).

```typescript
class SHA256 {
	constructor()
	hash(msg: Uint8Array): Uint8Array
	dispose(): void
}
```

**`constructor()`** -- Creates a new SHA256 instance. Throws if `init({ sha2: sha2Wasm })`
has not been called.

**`hash(msg: Uint8Array): Uint8Array`** -- Hashes the entire message and returns
a 32-byte `Uint8Array` digest. The message can be any length (including empty).
Large messages are internally chunked and streamed through the WASM hash function,
so memory usage stays constant regardless of input size.

**`dispose(): void`** -- Wipes all internal WASM buffers (hash state, input
buffer, output buffer). Call this when you are done with the instance.

---

### SHA512

Computes a SHA-512 hash (64-byte digest).

```typescript
class SHA512 {
	constructor()
	hash(msg: Uint8Array): Uint8Array
	dispose(): void
}
```

**`constructor()`** -- Creates a new SHA512 instance. Throws if not initialized.

**`hash(msg: Uint8Array): Uint8Array`** -- Returns a 64-byte digest.

**`dispose(): void`** -- Wipes all internal WASM buffers.

---

### SHA384

Computes a SHA-384 hash (48-byte digest). SHA-384 is a truncated variant of
SHA-512 with different initial values.

```typescript
class SHA384 {
	constructor()
	hash(msg: Uint8Array): Uint8Array
	dispose(): void
}
```

**`constructor()`** -- Creates a new SHA384 instance. Throws if not initialized.

**`hash(msg: Uint8Array): Uint8Array`** -- Returns a 48-byte digest.

**`dispose(): void`** -- Wipes all internal WASM buffers.

---

### HMAC_SHA256

Computes an HMAC-SHA256 authentication tag (32-byte output).

```typescript
class HMAC_SHA256 {
	constructor()
	hash(key: Uint8Array, msg: Uint8Array): Uint8Array
	dispose(): void
}
```

**`constructor()`** -- Creates a new HMAC_SHA256 instance. Throws if not
initialized.

**`hash(key: Uint8Array, msg: Uint8Array): Uint8Array`** -- Computes the
HMAC-SHA256 tag for the given message using the given key. Returns a 32-byte
`Uint8Array`. Keys longer than 64 bytes are automatically pre-hashed with
SHA-256 per RFC 2104 section 3.

**`dispose(): void`** -- Wipes all internal WASM buffers, including key material.

---

### HMAC_SHA512

Computes an HMAC-SHA512 authentication tag (64-byte output).

```typescript
class HMAC_SHA512 {
	constructor()
	hash(key: Uint8Array, msg: Uint8Array): Uint8Array
	dispose(): void
}
```

**`constructor()`** -- Creates a new HMAC_SHA512 instance. Throws if not
initialized.

**`hash(key: Uint8Array, msg: Uint8Array): Uint8Array`** -- Returns a 64-byte
HMAC tag. Keys longer than 128 bytes are pre-hashed with SHA-512.

**`dispose(): void`** -- Wipes all internal WASM buffers.

---

### HMAC_SHA384

Computes an HMAC-SHA384 authentication tag (48-byte output).

```typescript
class HMAC_SHA384 {
	constructor()
	hash(key: Uint8Array, msg: Uint8Array): Uint8Array
	dispose(): void
}
```

**`constructor()`** -- Creates a new HMAC_SHA384 instance. Throws if not
initialized.

**`hash(key: Uint8Array, msg: Uint8Array): Uint8Array`** -- Returns a 48-byte
HMAC tag. Keys longer than 128 bytes are pre-hashed with SHA-384.

**`dispose(): void`** -- Wipes all internal WASM buffers.

---

### HKDF_SHA256

RFC 5869 HMAC-based Extract-and-Expand Key Derivation Function over
HMAC-SHA256. Use HKDF when you need to derive one or more keys from a shared
secret (e.g. after a Diffie-Hellman exchange) or to separate keys for different
purposes from a single source of keying material.

`HKDF_SHA256` should be the default choice. `HKDF_SHA384` does not exist.

```typescript
class HKDF_SHA256 {
	constructor()
	extract(salt: Uint8Array | null, ikm: Uint8Array): Uint8Array
	expand(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array
	derive(ikm: Uint8Array, salt: Uint8Array | null, info: Uint8Array, length: number): Uint8Array
	dispose(): void
}
```

**`constructor()`** -- Creates a new HKDF_SHA256 instance. Throws if
`init({ sha2: sha2Wasm })` has not been called.

**`extract(salt, ikm): Uint8Array`** -- RFC 5869 section 2.2. Computes
`PRK = HMAC-SHA256(salt, IKM)`. Returns a 32-byte pseudorandom key. If `salt`
is `null` or empty, defaults to 32 zero bytes per RFC section 2.2.

**`expand(prk, info, length): Uint8Array`** -- RFC 5869 section 2.3. Derives
`length` bytes of output keying material from a 32-byte PRK. `info` provides
application-specific context (can be empty). `length` must be between 1 and
8160 (255 x 32). Throws `RangeError` if `prk` is not exactly 32 bytes or if
`length` is out of range.

**`derive(ikm, salt, info, length): Uint8Array`** -- One-shot: calls
`extract(salt, ikm)` then `expand(prk, info, length)`. This is the correct
path for most callers. `extract()` and `expand()` are exposed separately for
advanced use cases such as key separation and ratchets -- callers who reach for
them should know why.

**`dispose(): void`** -- Releases the internal HMAC instance.

---

### HKDF_SHA512

Identical to `HKDF_SHA256` but uses HMAC-SHA512 internally. HashLen is 64, so
PRK must be exactly 64 bytes and maximum output length is 16320 (255 x 64).

```typescript
class HKDF_SHA512 {
	constructor()
	extract(salt: Uint8Array | null, ikm: Uint8Array): Uint8Array
	expand(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array
	derive(ikm: Uint8Array, salt: Uint8Array | null, info: Uint8Array, length: number): Uint8Array
	dispose(): void
}
```

**`extract(salt, ikm)`** -- If `salt` is `null` or empty, defaults to 64 zero
bytes.

**`expand(prk, info, length)`** -- PRK must be exactly 64 bytes. `length` must
be between 1 and 16320. Throws `RangeError` otherwise.

> [!NOTE]
> HKDF is a pure TypeScript composition over the WASM-backed HMAC classes.
> It does not introduce new WASM code or new `init()` modules. Initializing
> `sha2` is sufficient.

**Usage example:**

```typescript
import { init, HKDF_SHA256, bytesToHex } from 'leviathan-crypto'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await init({ sha2: sha2Wasm })

const hkdf = new HKDF_SHA256()
const ikm = new Uint8Array(32) // your input keying material
const salt = crypto.getRandomValues(new Uint8Array(32))
const info = new TextEncoder().encode('my-app-v1-encryption-key')

const key = hkdf.derive(ikm, salt, info, 32)
console.log('Derived key:', bytesToHex(key))

hkdf.dispose()
```

---

## Usage Examples

### Example 1: Hash a message with SHA-256

The most common operation: hash a string and get a hex-encoded digest.

```typescript
import { init, SHA256, bytesToHex, utf8ToBytes } from 'leviathan-crypto'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

// Step 1: Initialize the SHA-2 WASM module (do this once at app startup)
await init({ sha2: sha2Wasm })

// Step 2: Create a SHA256 instance
const sha = new SHA256()

// Step 3: Hash a message
// utf8ToBytes converts a string to a Uint8Array
const message = utf8ToBytes('Hello, world!')
const digest = sha.hash(message)

// Step 4: Convert the digest to a hex string for display or storage
console.log(bytesToHex(digest))
// => "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3"

// Step 5: Clean up -- wipes hash state from WASM memory
sha.dispose()
```

### Example 2: Hash binary data (e.g., a file)

SHA-256 works on raw bytes, not just strings. You can hash any `Uint8Array`,
including file contents read from a `<input type="file">` element or a fetch
response.

```typescript
import { init, SHA256, bytesToHex } from 'leviathan-crypto'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await init({ sha2: sha2Wasm })

// Suppose you have file contents as an ArrayBuffer (from FileReader, fetch, etc.)
const response = await fetch('https://example.com/file.bin')
const buffer = new Uint8Array(await response.arrayBuffer())

const sha = new SHA256()
const digest = sha.hash(buffer)
console.log('SHA-256:', bytesToHex(digest))

sha.dispose()
```

The library handles large inputs automatically -- it streams the data through
the WASM hash function in chunks, so you do not need to worry about memory.

### Example 3: Using SHA-512 or SHA-384

The API is identical for all three hash variants. Only the output size differs.

```typescript
import { init, SHA256, SHA384, SHA512, bytesToHex, utf8ToBytes } from 'leviathan-crypto'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await init({ sha2: sha2Wasm })

const msg = utf8ToBytes('Same message, different hashes')

const sha256 = new SHA256()
const sha384 = new SHA384()
const sha512 = new SHA512()

console.log('SHA-256 (32 bytes):', bytesToHex(sha256.hash(msg)))
console.log('SHA-384 (48 bytes):', bytesToHex(sha384.hash(msg)))
console.log('SHA-512 (64 bytes):', bytesToHex(sha512.hash(msg)))

sha256.dispose()
sha384.dispose()
sha512.dispose()
```

### Example 4: Generate and verify an HMAC

Use HMAC when you need to prove that a message was created by someone who holds
a secret key. A typical pattern: one side generates a tag, the other side
recomputes the tag with the same key and checks that they match.

```typescript
import {
	init, HMAC_SHA256, constantTimeEqual, randomBytes,
	bytesToHex, utf8ToBytes
} from 'leviathan-crypto'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await init({ sha2: sha2Wasm })

// Generate a random 32-byte key (do this once, store it securely)
const key = randomBytes(32)

const hmac = new HMAC_SHA256()
const message = utf8ToBytes('Transfer $100 to Alice')

// --- Sender side: generate the tag ---
const tag = hmac.hash(key, message)
console.log('HMAC tag:', bytesToHex(tag))

// Send both `message` and `tag` to the recipient...

// --- Recipient side: verify the tag ---
// The recipient has the same key and recomputes the tag
const recomputed = hmac.hash(key, message)

// Use constant-time comparison to check the tags
if (constantTimeEqual(tag, recomputed)) {
	console.log('Message is authentic -- it was not tampered with')
} else {
	console.log('WARNING: message has been modified or key is wrong')
}

hmac.dispose()
```

### Example 5: HMAC verification -- the wrong way vs. the right way

This is important enough to call out separately. The difference between these
two approaches is the difference between a secure system and a broken one.

```typescript
import { init, HMAC_SHA256, constantTimeEqual, bytesToHex } from 'leviathan-crypto'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await init({ sha2: sha2Wasm })
const hmac = new HMAC_SHA256()

// Suppose you received a message with a tag and you recomputed the expected tag:
const receivedTag = hmac.hash(key, message)
const expectedTag = hmac.hash(key, message)

// WRONG -- timing attack vulnerable!
// JavaScript's === operator compares byte-by-byte and returns false as soon as
// it finds a mismatch. An attacker can measure the response time to figure out
// how many leading bytes of the tag are correct, then forge a valid tag one
// byte at a time.
if (bytesToHex(receivedTag) === bytesToHex(expectedTag)) {
	// This "works" but is insecure
}

// RIGHT -- constant-time comparison
// constantTimeEqual always examines every byte, regardless of where the first
// difference is. The comparison takes the same amount of time whether zero
// bytes match or all bytes match.
if (constantTimeEqual(receivedTag, expectedTag)) {
	// This is secure
}

hmac.dispose()
```

### Example 6: Using HMAC-SHA512 for higher security

The pattern is identical to HMAC-SHA256. Use a 64-byte key for full security.

```typescript
import { init, HMAC_SHA512, constantTimeEqual, randomBytes, utf8ToBytes } from 'leviathan-crypto'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await init({ sha2: sha2Wasm })

// 64-byte key for HMAC-SHA512
const key = randomBytes(64)
const hmac = new HMAC_SHA512()

const tag = hmac.hash(key, utf8ToBytes('Important message'))
// tag is a 64-byte Uint8Array

// Verify
const recomputed = hmac.hash(key, utf8ToBytes('Important message'))
console.log('Valid:', constantTimeEqual(tag, recomputed)) // true

hmac.dispose()
```

### Example 7: Hashing an empty input

SHA-2 is well-defined for empty inputs. This can be useful as a sanity check.

```typescript
import { init, SHA256, bytesToHex } from 'leviathan-crypto'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await init({ sha2: sha2Wasm })

const sha = new SHA256()
const digest = sha.hash(new Uint8Array(0))
console.log(bytesToHex(digest))
// => "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
// (This is the well-known SHA-256 hash of the empty string)

sha.dispose()
```

---

## Error Conditions

### Module not initialized

If you construct any SHA-2 class before calling `init({ sha2: sha2Wasm })`, the
constructor throws immediately:

```
Error: leviathan-crypto: call init({ sha2: ... }) before using this class
```

**Fix:** Call `await init({ sha2: sha2Wasm })` at application startup, before creating any
SHA-2 instances.

```typescript
// This will throw:
const sha = new SHA256() // Error!

// Do this instead:
await init({ sha2: sha2Wasm })
const sha = new SHA256() // OK
```

### HMAC key length

HMAC accepts keys of any length, including zero-length keys. However:

- **Keys shorter than the recommended minimum** (see the table in Security
  Notes) are zero-padded internally. They will produce valid HMAC tags, but the
  security of the MAC is limited by the key length, not the hash output size.
  A 16-byte key with HMAC-SHA256 provides at most 128 bits of security, not 256.
- **Keys longer than the hash block size** (64 bytes for HMAC-SHA256, 128 bytes
  for HMAC-SHA384 and HMAC-SHA512) are automatically pre-hashed to fit. This is
  standard behavior defined in RFC 2104 section 3 and is handled transparently.
- **Zero-length keys** are technically valid per the HMAC spec, but provide no
  authentication. Do not use a zero-length key in production.

### Empty message input

All hash and HMAC functions accept empty `Uint8Array` inputs (`new Uint8Array(0)`).
SHA-2 is well-defined for zero-length messages and will return the correct digest.

---

> ## Cross-References
>
> - [index](./README.md) — Project Documentation index
> - [architecture](./architecture.md) — architecture overview, module relationships, buffer layouts, and build pipeline
> - [asm_sha2](./asm_sha2.md) — WASM implementation details (AssemblyScript buffer layout, compression functions)
> - [sha3](./sha3.md) — alternative: SHA-3 family (immune to length extension attacks)
> - [serpent](./serpent.md) — SerpentSeal and SerpentCipher use HMAC-SHA256 and HKDF internally
> - [argon2id](./argon2id.md) — Argon2id password hashing; HKDF expands Argon2id root keys
> - [fortuna](./fortuna.md) — Fortuna CSPRNG uses SHA-256 for entropy accumulation
> - [utils](./utils.md) — `constantTimeEqual`, `bytesToHex`, `utf8ToBytes`, `randomBytes`
> - [sha2_audit.md](./sha2_audit.md) — SHA-2 implementation audit
> - [hmac_audit.md](./hmac_audit.md) — HMAC implementation audit
> - [hkdf_audit.md](./hkdf_audit.md) — HKDF implementation audit
