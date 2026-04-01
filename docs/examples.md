# Leviathan Crypto Library: Examples

>[!NOTE]
> This document provides an overview of the library's capabilities.
> For complete example sets and full API documentation, follow the links in each section header.

## High Level API

_Safe defaults, authentication built in, hand-holding included._

### [SerpentSeal](./serpent.md): authenticated encryption

The recommended one-shot cipher. Serpent-CBC + HMAC-SHA256 under the hood.
64-byte key is split internally into encryption and MAC keys.

```typescript
import { init, SerpentSeal, randomBytes } from 'leviathan-crypto'

await init(['serpent', 'sha2'])

const key = randomBytes(64)  // 32 bytes enc + 32 bytes MAC
const seal = new SerpentSeal()

const plaintext  = new TextEncoder().encode('Authenticated secret message.')
const ciphertext = seal.encrypt(key, plaintext)
const decrypted  = seal.decrypt(key, ciphertext)  // throws on tamper

console.log(new TextDecoder().decode(decrypted))
// => "Authenticated secret message."

seal.dispose()
```

---

### [XChaCha20Seal](./chacha20.md): authenticated encryption

The recommended ChaCha20 AEAD. Binds key at construction, generates a fresh
random 24-byte nonce on every `encrypt()` call. No nonce management needed.

```typescript
import { init, XChaCha20Seal, randomBytes } from 'leviathan-crypto'

await init(['chacha20'])

const seal = new XChaCha20Seal(randomBytes(32))

const plaintext  = new TextEncoder().encode('Authenticated secret message.')
const ciphertext = seal.encrypt(plaintext)               // nonce(24) || ct || tag(16)
const decrypted  = seal.decrypt(ciphertext)               // throws on tamper

console.log(new TextDecoder().decode(decrypted))
// => "Authenticated secret message."

// Optional: bind metadata without encrypting it
const metadata   = new TextEncoder().encode('document-v2')
const ct2        = seal.encrypt(plaintext, metadata)      // AAD bound to ciphertext
const pt2        = seal.decrypt(ct2, metadata)            // must pass same AAD

seal.dispose()
```

---

### [SerpentStreamSealer / SerpentStreamOpener](./serpent.md): incremental streaming AEAD

For data arriving in chunks — such as network streams, file processors, and live feeds —
buffering the full message isn't necessary.

```typescript
import { init, SerpentStreamSealer, SerpentStreamOpener, randomBytes } from 'leviathan-crypto'

await init(['serpent', 'sha2'])

const key       = randomBytes(64)
const chunkSize = 65536  // 64 KB

// ── Seal side ───────────────────────────────────────────────────────────────

const sealer = new SerpentStreamSealer(key, chunkSize)
const header = sealer.header()    // send this to the opener before any chunks

const chunk0    = sealer.seal(plaintext0)      // exactly chunkSize bytes
const chunk1    = sealer.seal(plaintext1)
const lastChunk = sealer.final(lastPlaintext)  // wipes key if size ≤ chunkSize

// ── Open side ───────────────────────────────────────────────────────────────

const opener = new SerpentStreamOpener(key, header)

const pt0 = opener.open(chunk0)
const pt1 = opener.open(chunk1)
const ptN = opener.open(lastChunk)  // detects final chunk, wipes key on return

// Reordering, truncation, and cross-stream splicing all throw on open()
```

---

### [XChaCha20StreamSealer / XChaCha20StreamOpener](./chacha20.md): incremental streaming AEAD

For data arriving in chunks. Each chunk gets its own random nonce and is
cryptographically bound to its position in the stream. Reorder, truncation,
and cross-stream splicing all fail authentication.

```typescript
import { init, XChaCha20StreamSealer, XChaCha20StreamOpener, randomBytes } from 'leviathan-crypto'

await init(['chacha20'])

const key       = randomBytes(32)
const chunkSize = 65536  // 1024..65536

// ── Seal side ───────────────────────────────────────────────────────────────

const sealer = new XChaCha20StreamSealer(key, chunkSize)
const header = sealer.header()    // 20 bytes: stream_id(16) + chunkSize(4)

const chunk0    = sealer.seal(plaintext0)      // exactly chunkSize bytes
const chunk1    = sealer.seal(plaintext1)
const lastChunk = sealer.final(lastPlaintext)  // ≤ chunkSize, wipes key

// ── Open side ───────────────────────────────────────────────────────────────

const opener = new XChaCha20StreamOpener(key, header)

const pt0 = opener.open(chunk0)
const pt1 = opener.open(chunk1)
const ptN = opener.open(lastChunk)  // detects final chunk, wipes key
```

#### Framed mode (for network transports)

```typescript
// Each sealed chunk gets a 4-byte big-endian length prefix
const sealer = new XChaCha20StreamSealer(key, 65536, { framed: true })
const header = sealer.header()
const frame0 = sealer.seal(plaintext0)    // len(4) || isLast(1) || nonce(24) || ct || tag(16)
const frame1 = sealer.final(plaintext1)

// feed() accepts arbitrary byte slices and reassembles frames internally
const opener = new XChaCha20StreamOpener(key, header, { framed: true })
const results = opener.feed(networkBytes)  // Uint8Array[] — zero or more plaintexts
```

#### With AAD

```typescript
const metadata = new TextEncoder().encode('backup-2026-04-01')

const sealer = new XChaCha20StreamSealer(key, 65536, { aad: metadata })
// ... seal chunks ...

const opener = new XChaCha20StreamOpener(key, header, { aad: metadata })
// AAD mismatch → authentication failure on every chunk
```

---


### [SerpentStream](./serpent.md): chunked large payload

One-shot seal/open for large data. Handles chunking internally.

```typescript
import { init, SerpentStream, randomBytes } from 'leviathan-crypto'

await init(['serpent', 'sha2'])

const key    = randomBytes(32)    // 32-byte key: HKDF handles expansion
const stream = new SerpentStream()

const plaintext  = new Uint8Array(1024 * 1024)   // 1 MB
crypto.getRandomValues(plaintext)

const ciphertext = stream.seal(key, plaintext)   // default 64 KB chunks
const decrypted  = stream.open(key, ciphertext)

stream.dispose()
```

---

### [XChaCha20Poly1305Pool](./chacha20_pool.md): parallel authenticated encryption

Worker pool for maximum throughput across multiple cores. Each worker runs
an isolated WASM instance.

```typescript
import { init, XChaCha20Poly1305Pool, randomBytes } from 'leviathan-crypto'

await init(['chacha20'])

const pool = await XChaCha20Poly1305Pool.create({ workers: 4 })
const key  = randomBytes(32)

// Encrypt many messages concurrently
const messages = ['msg-1', 'msg-2', 'msg-3', 'msg-4']
const encrypted = await Promise.all(
  messages.map(msg => {
    const nonce = randomBytes(24)
    const pt    = new TextEncoder().encode(msg)
    return pool.encrypt(key.slice(), nonce, pt)
  })
)

pool.dispose()
```

---

### [SHA-256 hash + HMAC verify](./sha2.md)

Hash a message, then use HMAC to authenticate it. Always use
[`constantTimeEqual`](./utils.md#constanttimeequal) for tag comparison.

```typescript
import { init, SHA256, HMAC_SHA256, constantTimeEqual, randomBytes, bytesToHex, utf8ToBytes } from 'leviathan-crypto'

await init(['sha2'])

// Hash
const sha = new SHA256()
const digest = sha.hash(utf8ToBytes('Hello, world!'))
console.log(bytesToHex(digest))
// => "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3"
sha.dispose()

// HMAC: generate and verify
const key     = randomBytes(32)
const hmac    = new HMAC_SHA256()
const message = utf8ToBytes('Transfer $100 to Alice')
const tag     = hmac.hash(key, message)

// Verify: always constant-time
const recomputed = hmac.hash(key, message)
if (constantTimeEqual(tag, recomputed)) {
  console.log('Authentic.')
} else {
  console.log('Tampered!')
}

hmac.dispose()
```

---

### [Fortuna CSPRNG](./fortuna.md)

Cryptographically secure random bytes with forward secrecy and 32 entropy pools.

```typescript
import { init, Fortuna } from 'leviathan-crypto'

await init(['serpent', 'sha2'])

const rng = await Fortuna.create()

const key   = rng.get(32)  // 256-bit encryption key
const nonce = rng.get(24)  // 192-bit XChaCha20 nonce

rng.stop()  // wipes key material
```

---

### [Utilities](./utils.md)

No `init()` required.

```typescript
import { hexToBytes, bytesToHex, utf8ToBytes, randomBytes, constantTimeEqual, wipe } from 'leviathan-crypto'

// Encoding round-trips
const bytes = hexToBytes('ac1dc0de')
console.log(bytesToHex(bytes))  // => "ac1dc0de"

// Random keys
const key   = randomBytes(32)
const nonce = randomBytes(24)

// Constant-time comparison
const a = randomBytes(16)
let b   = randomBytes(16)
while (constantTimeEqual(a, b)) b = randomBytes(16)

console.log(constantTimeEqual(a, b))  // false

// Wipe sensitive material
wipe(key)  // key is now all zeroes
```

---

> [!CAUTION]
> # Danger Zone ⚠ Raw primitives with no built-in authentication
>
> *The classes below give you direct access to unauthenticated cipher modes and
> low-level MAC and KDF primitives. They exist for protocol implementors and
> advanced use cases. If you are building general-purpose encryption, stop here
> and use `SerpentSeal` or `XChaCha20Poly1305` instead.*

### [SerpentCbc](./serpent.md): raw CBC mode

*Provides confidentiality only: an attacker can modify ciphertext without
detection. Pair with `HMAC_SHA256` using Encrypt-then-MAC, or use `SerpentSeal`.*

```typescript
import { init, SerpentCbc, randomBytes } from 'leviathan-crypto'

await init(['serpent'])

const key = randomBytes(32)
const iv  = randomBytes(16)  // unique per message: never reuse with the same key

const cbc = new SerpentCbc({ dangerUnauthenticated: true })

const ciphertext = cbc.encrypt(key, iv, new TextEncoder().encode('raw and naked'))
const decrypted  = cbc.decrypt(key, iv, ciphertext)

cbc.dispose()
```

---

### [SerpentCtr](./serpent.md): raw CTR mode

*Unauthenticated stream mode. A single flipped ciphertext bit flips the
corresponding plaintext bit with no error. Pair with `HMAC_SHA256` (Encrypt-then-MAC).*

```typescript
import { init, SerpentCtr, randomBytes } from 'leviathan-crypto'

await init(['serpent'])

const key   = randomBytes(32)
const nonce = randomBytes(16)  // never reuse with the same key

const ctr = new SerpentCtr({ dangerUnauthenticated: true })

ctr.beginEncrypt(key, nonce)
const ct1 = ctr.encryptChunk(new Uint8Array([1, 2, 3, 4]))
const ct2 = ctr.encryptChunk(new Uint8Array([5, 6, 7, 8]))

ctr.beginDecrypt(key, nonce)
const pt1 = ctr.decryptChunk(ct1)  // => [1, 2, 3, 4]
const pt2 = ctr.decryptChunk(ct2)  // => [5, 6, 7, 8]

ctr.dispose()
```

---

### [Serpent](./serpent.md): raw ECB block cipher

*Single 16-byte block operations with no mode, no IV, no authentication.
Identical plaintext blocks produce identical ciphertext. Almost never
what you want: use `SerpentSeal` unless you are implementing a custom mode.*

```typescript
import { init, Serpent, randomBytes } from 'leviathan-crypto'

await init(['serpent'])

const cipher = new Serpent()
cipher.loadKey(randomBytes(32))

const block = new Uint8Array([
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
])

const encrypted = cipher.encryptBlock(block)
const decrypted = cipher.decryptBlock(encrypted)  // identical to block

cipher.dispose()
```

---

### [ChaCha20](./chacha20.md): raw stream cipher

*Keystream XOR with no authentication tag. Bit flips in ciphertext produce
bit flips in plaintext with no error. Use `XChaCha20Poly1305` instead, or
pair with `Poly1305` (Encrypt-then-MAC).*

```typescript
import { init, ChaCha20, randomBytes } from 'leviathan-crypto'

await init(['chacha20'])

const key   = randomBytes(32)
const nonce = randomBytes(12)  // 12-byte nonce for raw ChaCha20
const cipher = new ChaCha20()

cipher.beginEncrypt(key, nonce)
const ct1 = cipher.encryptChunk(new Uint8Array([1, 2, 3, 4]))
const ct2 = cipher.encryptChunk(new Uint8Array([5, 6, 7, 8]))

cipher.beginDecrypt(key, nonce)
const pt1 = cipher.decryptChunk(ct1)  // => [1, 2, 3, 4]
const pt2 = cipher.decryptChunk(ct2)  // => [5, 6, 7, 8]

cipher.dispose()
```

---

### [Poly1305](./chacha20.md): standalone one-time MAC

*The key must never be reused across messages: reuse allows an attacker to
recover `r` and forge arbitrary tags. The AEAD classes handle key derivation
automatically; use them unless you have a specific reason not to.*

```typescript
import { init, Poly1305, randomBytes } from 'leviathan-crypto'

await init(['chacha20'])

// Key must be fresh for every message: derive with ChaCha20 counter=0
// or use a KDF. Never use the same key twice.
const key     = randomBytes(32)
const message = new TextEncoder().encode('authenticate this')

const mac = new Poly1305()
const tag = mac.mac(key, message)  // 16-byte tag

mac.dispose()
```

---

### [XChaCha20Poly1305](./chacha20.md): stateless AEAD primitive

*The RFC-faithful stateless primitive. Caller is responsible for nonce
management — reusing a nonce with the same key is catastrophic. Use
`XChaCha20Seal` unless you need explicit nonce control for protocol
interoperability.*

```typescript
import { init, XChaCha20Poly1305, randomBytes, utf8ToBytes, bytesToUtf8 } from 'leviathan-crypto'

await init(['chacha20'])

const key   = randomBytes(32)
const nonce = randomBytes(24)  // caller must guarantee uniqueness per key
const aead  = new XChaCha20Poly1305()

const ciphertext = aead.encrypt(key, nonce, utf8ToBytes('Hello, world!'))
const decrypted  = aead.decrypt(key, nonce, ciphertext)  // throws on tamper

console.log(bytesToUtf8(decrypted))  // => "Hello, world!"

aead.dispose()
```

---

### [ChaCha20Poly1305](./chacha20.md): stateless AEAD primitive (RFC 8439)

*12-byte nonce variant. Same caller-managed-nonce hazard as `XChaCha20Poly1305`.
The 12-byte nonce space is small enough that random generation risks collision
at scale. Prefer `XChaCha20Seal` for new protocols.*

```typescript
import { init, ChaCha20Poly1305, randomBytes, utf8ToBytes, bytesToUtf8 } from 'leviathan-crypto'

await init(['chacha20'])

const key   = randomBytes(32)
const nonce = randomBytes(12)  // 12-byte nonce: collision risk at ~2^32 messages
const aead  = new ChaCha20Poly1305()

const ciphertext = aead.encrypt(key, nonce, utf8ToBytes('Hello, world!'))
const decrypted  = aead.decrypt(key, nonce, ciphertext)

aead.dispose()
```

---

### [HKDF_SHA256](./sha2.md): manual key derivation

*Extract-then-expand. The `info` parameter is your domain separator: different
values for different derived keys from the same root material.*

```typescript
import { init, HKDF_SHA256, randomBytes, utf8ToBytes, bytesToHex } from 'leviathan-crypto'

await init(['sha2'])

const hkdf = new HKDF_SHA256()

const ikm  = randomBytes(32)                              // input keying material
const salt = randomBytes(32)                              // random, per-session
const info = utf8ToBytes('my-app-v1-encryption-key')     // domain separation

const derived = hkdf.derive(ikm, salt, info, 64)          // 64 bytes out
const encKey  = derived.subarray(0, 32)                   // first 32: enc key
const macKey  = derived.subarray(32, 64)                  // last 32: MAC key

console.log(bytesToHex(encKey))

hkdf.dispose()
```

---

### [SHAKE128 / SHAKE256](./sha3.md): XOF squeeze

*Extendable output functions: squeeze as many bytes as you need from a single
absorption. The capacity (not the output length) determines security: SHAKE128
provides 128-bit security, SHAKE256 provides 256-bit security, regardless of
how many bytes you squeeze.*

```typescript
import { init, SHAKE256, randomBytes, bytesToHex } from 'leviathan-crypto'

await init(['sha3'])

const shake   = new SHAKE256()
const entropy = randomBytes(32)

// Squeeze 96 bytes in one shot
const output = shake.hash(entropy, 96)
console.log(bytesToHex(output))  // 192 hex chars

// Or squeeze incrementally
shake.absorb(entropy)
const block1 = shake.squeeze(32)  // first 32 bytes
const block2 = shake.squeeze(32)  // next 32 bytes
const block3 = shake.squeeze(32)  // next 32 bytes
// block1 + block2 + block3 === output

shake.dispose()
```

---

> ## Cross-References
>
> - [index](./README.md) — Project Documentation index
> - [architecture](./architecture.md) — architecture overview, module relationships, buffer layouts, and build pipeline
> - [cdn](./cdn.md) CDN usage examples. _"no bundler? no problem"_
