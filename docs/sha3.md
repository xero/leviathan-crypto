# SHA3 TypeScript API Reference

> [!NOTE]
> SHA-3 hash functions and SHAKE XOFs (TypeScript API)

## Overview

The SHA-3 family provides six hash functions standardized in **FIPS 202**: four
fixed-output hash functions (SHA3-224, SHA3-256, SHA3-384, SHA3-512) and two
extendable-output functions, or XOFs (SHAKE128, SHAKE256). All six are built on
the **Keccak sponge construction** -- a fundamentally different design from the
Merkle-Damgard structure used by SHA-2.

SHA-3 is **not** a replacement for SHA-2. Both are considered secure, and both are
standardized by NIST. SHA-3 exists to provide **defense-in-depth**: if a flaw is
ever discovered in SHA-2, SHA-3 is completely unaffected because it uses a different
mathematical foundation. Think of it as insurance -- you may never need it, but if
you do, you will be very glad it is there.

The SHAKE XOFs are particularly flexible. Unlike SHA3-256, which always produces
exactly 32 bytes, SHAKE128 and SHAKE256 can produce variable-length output -- you
tell them how many bytes you want. This is useful for key derivation, generating
nonces, or any situation where you need more (or fewer) bytes than a standard hash
provides.

One key advantage of SHA-3 over SHA-2: **SHA-3 is immune to length extension
attacks.** With SHA-2, if you know `SHA256(secret + message)` but not the secret,
you can compute `SHA256(secret + message + padding + extra)` without knowing the
secret. SHA-3's sponge construction makes this impossible.

---

## Security Notes

> [!IMPORTANT]
> Read these before using the API. Misusing hash functions is one of the most
> common sources of security vulnerabilities.

- **Length extension immunity.** Unlike SHA-2, the SHA-3 sponge construction does
  not leak enough internal state for length extension attacks. Computing
  `SHA3(secret + message)` does not let an attacker forge `SHA3(secret + message + extra)`.
  That said, **HMAC is still the correct way to build a MAC** -- do not use raw
  `SHA3(key + message)` as a MAC construction, even though it is not vulnerable to
  length extension. HMAC provides a formally proven security reduction.

- **SHAKE output is unbounded.** SHAKE128 and SHAKE256 are full XOFs — output
  length is unbounded. Request any number of bytes via `hash()`, or drive the
  sponge directly with `absorb()` / `squeeze()`. The only constraint is
  `outputLength >= 1`.

- **Not for password hashing.** SHA-3 is a fast hash — that is the opposite of
  what you want for password storage. Passwords must be hashed with a slow,
  memory-hardened algorithm like **Argon2id**. See [argon2id.md](./argon2id.md) for
  usage patterns including passphrase-based encryption with leviathan primitives.

- **Call `dispose()` when finished.** Every SHA-3 class wraps a WASM module that
  stores Keccak state in linear memory. Calling `dispose()` zeroes all internal
  state (the 200-byte lane matrix, input buffer, output buffer, and metadata).
  If you skip `dispose()`, key material or intermediate hash state may persist
  in memory.

---

## Module Init

Each module subpath exports its own `init()` for consumers who want
tree-shakeable imports.

### `init(mode?, opts?)`

Initializes only the sha3 WASM binary. Equivalent to calling the
root `init(['sha3'], mode, opts)` but without pulling the other three
modules into the bundle.

**Signature:**

```typescript
async function init(mode?: Mode, opts?: InitOpts): Promise<void>
```

**Usage:**

```typescript
import { init, SHA3_256 } from 'leviathan-crypto/sha3'

await init()
const sha3 = new SHA3_256()
```

---

## API Reference

All SHA-3 classes require initialization before use. Either the root `init()`:

```typescript
import { init } from 'leviathan-crypto'

await init('sha3')
```

Both `init('sha3')` and `init(['sha3'])` are valid — the root `init()` accepts
a single `Module` string or an array.

Or the subpath `init()`:

```typescript
import { init } from 'leviathan-crypto/sha3'

await init()
```

If you use SHA-3 classes without calling `init()` first, the constructor
will throw an error.

---

### SHA3_224

Fixed-output hash function. Produces a **28-byte** (224-bit) digest.

```typescript
class SHA3_224 {
	constructor()
	hash(msg: Uint8Array): Uint8Array   // returns 28 bytes
	dispose(): void
}
```

---

### SHA3_256

Fixed-output hash function. Produces a **32-byte** (256-bit) digest. This is the
most commonly used SHA-3 variant -- 256-bit security is suitable for most
applications.

```typescript
class SHA3_256 {
	constructor()
	hash(msg: Uint8Array): Uint8Array   // returns 32 bytes
	dispose(): void
}
```

---

### SHA3_384

Fixed-output hash function. Produces a **48-byte** (384-bit) digest.

```typescript
class SHA3_384 {
	constructor()
	hash(msg: Uint8Array): Uint8Array   // returns 48 bytes
	dispose(): void
}
```

---

### SHA3_512

Fixed-output hash function. Produces a **64-byte** (512-bit) digest. Use this when
you need the highest security margin.

```typescript
class SHA3_512 {
	constructor()
	hash(msg: Uint8Array): Uint8Array   // returns 64 bytes
	dispose(): void
}
```

---

### SHAKE128

Extendable-output function (XOF). Produces **variable-length** output — any
number of bytes you request. 128-bit security level.

```typescript
class SHAKE128 {
	constructor()
	hash(msg: Uint8Array, outputLength: number): Uint8Array
	absorb(msg: Uint8Array): this
	squeeze(n: number): Uint8Array
	reset(): this
	dispose(): void
}
```

| Method | Description |
|--------|-------------|
| `hash(msg, outputLength)` | One-shot: reset, absorb, squeeze. Safe on a dirty instance. |
| `absorb(msg)` | Feed data into the sponge. Chainable. Throws if called after `squeeze()`. |
| `squeeze(n)` | Pull `n` bytes of XOF output. Continues from where the last `squeeze()` left off. |
| `reset()` | Return to a fresh, zeroed state. Chainable. Safe at any point. |
| `dispose()` | Zero all WASM state and the TS-side block buffer. |

**`outputLength`** / **`n`** must be `>= 1`. Values below 1 throw a `RangeError`.

---

### SHAKE256

Extendable-output function (XOF). Produces **variable-length** output — any
number of bytes you request. 256-bit security level.

```typescript
class SHAKE256 {
	constructor()
	hash(msg: Uint8Array, outputLength: number): Uint8Array
	absorb(msg: Uint8Array): this
	squeeze(n: number): Uint8Array
	reset(): this
	dispose(): void
}
```

| Method | Description |
|--------|-------------|
| `hash(msg, outputLength)` | One-shot: reset, absorb, squeeze. Safe on a dirty instance. |
| `absorb(msg)` | Feed data into the sponge. Chainable. Throws if called after `squeeze()`. |
| `squeeze(n)` | Pull `n` bytes of XOF output. Continues from where the last `squeeze()` left off. |
| `reset()` | Return to a fresh, zeroed state. Chainable. Safe at any point. |
| `dispose()` | Zero all WASM state and the TS-side block buffer. |

**`outputLength`** / **`n`** must be `>= 1`. Values below 1 throw a `RangeError`.

---

## Incremental XOF API (`absorb` / `squeeze` / `reset`)

For use cases where you need to pull output in multiple steps — key derivation,
mask generation, protocol-specific domain separation — the SHAKE classes expose
a streaming interface alongside the one-shot `hash()`.

### State machine

| State       | Valid calls                     |
|-------------|---------------------------------|
| fresh       | `absorb()`, `hash()`, `reset()` |
| absorbing   | `absorb()`, `squeeze()`, `hash()`, `reset()` |
| squeezing   | `squeeze()`, `hash()`, `reset()` |

Calling `absorb()` while squeezing throws:
`"SHAKE128: cannot absorb after squeeze — call reset() first"`

`hash()` always resets before running — safe to call on a dirty instance.

### Example

```typescript
import { init, SHAKE256 } from 'leviathan-crypto'

await init('sha3')

const xof = new SHAKE256()
xof.absorb(ikm)             // input key material
xof.absorb(salt)            // additional context

const encKey  = xof.squeeze(32)   // 256-bit encryption key
const macKey  = xof.squeeze(32)   // 256-bit MAC key
const nonce   = xof.squeeze(12)   // 96-bit nonce

xof.dispose()
```

---

## Usage Examples

### Example 1: Hash a string with SHA3-256

The most common use case -- hash some data and get a hex digest.

```typescript
import { init, SHA3_256, bytesToHex, utf8ToBytes } from 'leviathan-crypto'

// Initialize the SHA-3 WASM module (once, at startup)
await init('sha3')

// Create a hasher
const sha3 = new SHA3_256()

// Hash a UTF-8 string
const message = utf8ToBytes('Hello, world!')
const digest = sha3.hash(message)

console.log(bytesToHex(digest))
// 32 bytes (64 hex characters) of SHA3-256 output

// Clean up -- zeroes all WASM state
sha3.dispose()
```

---

### Example 2: Hash binary data with SHA3-512

```typescript
import { init, SHA3_512, bytesToHex } from 'leviathan-crypto'

await init('sha3')

const sha3 = new SHA3_512()

// Hash raw bytes (e.g., a file, a key, a nonce)
const data = new Uint8Array([0x01, 0x02, 0x03, 0x04])
const digest = sha3.hash(data)

console.log(bytesToHex(digest))
// 64 bytes (128 hex characters) of SHA3-512 output

sha3.dispose()
```

---

### Example 3: Hash multiple messages

Each call to `hash()` is independent -- the internal state is reset automatically.
You can reuse the same class instance for multiple hashes.

```typescript
import { init, SHA3_256, bytesToHex, utf8ToBytes } from 'leviathan-crypto'

await init('sha3')

const sha3 = new SHA3_256()

const hash1 = sha3.hash(utf8ToBytes('first message'))
const hash2 = sha3.hash(utf8ToBytes('second message'))
const hash3 = sha3.hash(utf8ToBytes('first message'))

// hash1 and hash3 are identical -- same input, same output
console.log(bytesToHex(hash1) === bytesToHex(hash3))  // true

// hash2 is different -- different input
console.log(bytesToHex(hash1) === bytesToHex(hash2))  // false

sha3.dispose()
```

---

### Example 4: SHAKE128 variable-length output

SHAKE lets you choose exactly how many bytes of output you need. This is useful
for key derivation or generating fixed-size tokens.

```typescript
import { init, SHAKE128, bytesToHex, utf8ToBytes } from 'leviathan-crypto'

await init('sha3')

const shake = new SHAKE128()

const seed = utf8ToBytes('my-application-seed')

// Derive a 16-byte key (128 bits)
const key128 = shake.hash(seed, 16)
console.log('16-byte key:', bytesToHex(key128))

// Derive a 32-byte key (256 bits) from the same seed
const key256 = shake.hash(seed, 32)
console.log('32-byte key:', bytesToHex(key256))

// The 16-byte output is NOT a prefix of the 32-byte output --
// each call resets state, re-absorbs, and squeezes independently.
// However, for SHAKE, the first 16 bytes of the 32-byte output
// ARE identical to the 16-byte output (this is how XOFs work).

shake.dispose()
```

---

### Example 5: SHAKE256 for key derivation

```typescript
import { init, SHAKE256, bytesToHex } from 'leviathan-crypto'

await init('sha3')

const shake = new SHAKE256()

// Derive a 48-byte key from raw entropy
const entropy = crypto.getRandomValues(new Uint8Array(32))
const derivedKey = shake.hash(entropy, 48)

console.log('Derived key:', bytesToHex(derivedKey))
// 48 bytes (96 hex characters) of SHAKE256 output

shake.dispose()
```

---

### Example 6: SHA-256 vs SHA3-256 -- different algorithms, different output

SHA-256 (from the SHA-2 family) and SHA3-256 are completely different algorithms.
They produce different output for the same input. Neither is "better" -- both
are secure. SHA3-256 adds defense-in-depth.

```typescript
import { init, SHA256, SHA3_256, bytesToHex, utf8ToBytes } from 'leviathan-crypto'

// Initialize both modules
await init(['sha2', 'sha3'])

const sha2 = new SHA256()
const sha3 = new SHA3_256()

const message = utf8ToBytes('abc')

const sha2Digest = sha2.hash(message)
const sha3Digest = sha3.hash(message)

console.log('SHA-256:  ', bytesToHex(sha2Digest))
console.log('SHA3-256: ', bytesToHex(sha3Digest))
// These are completely different values -- different algorithms

sha2.dispose()
sha3.dispose()
```

---

### Example 7: Hashing empty input

All hash functions accept empty input. This is well-defined and produces a
deterministic output.

```typescript
import { init, SHA3_256, bytesToHex } from 'leviathan-crypto'

await init('sha3')

const sha3 = new SHA3_256()
const digest = sha3.hash(new Uint8Array(0))

console.log(bytesToHex(digest))
// The SHA3-256 hash of empty input -- a fixed, known value

sha3.dispose()
```

---

## Error Conditions

### `init('sha3')` not called

If you construct a SHA-3 class before initializing the module, the constructor
throws immediately:

```
Error: leviathan-crypto: call init(['sha3']) before using this class
```

**Fix:** Call `await init('sha3')` once at application startup, before creating
any SHA-3 class instances.

---

### SHAKE output length out of range

SHAKE128 and SHAKE256 require `outputLength >= 1`. Passing 0 or a negative number
throws a `RangeError`:

```
RangeError: outputLength must be >= 1 (got 0)
```

**Fix:** Request at least 1 byte.

---

### SHAKE absorb after squeeze

Calling `absorb()` after `squeeze()` has been called throws an `Error`. The sponge
has been padded and finalized — further absorption is not meaningful.

```
Error: SHAKE128: cannot absorb after squeeze — call reset() first
```

**Fix:** Call `reset()` to return the instance to a fresh state before absorbing
new data.

---

### Empty input

Passing an empty `Uint8Array` (length 0) is **not** an error. All SHA-3 and SHAKE
functions produce valid, deterministic output for empty input. The sponge simply
absorbs zero bytes and then squeezes.

---

## Cross-References

- [README.md](./README.md): Project overview and quick-start guide
- [asm_sha3.md](./asm_sha3.md): WASM implementation details (buffer layout, Keccak internals, variant parameters)
- [sha2.md](./sha2.md): Alternative: SHA-2 family (SHA-256, SHA-384, SHA-512) and HMAC
- [utils.md](./utils.md): Encoding utilities: `bytesToHex`, `hexToBytes`, `utf8ToBytes`
- [architecture.md](./architecture.md): Library architecture and `init()` API
