# Examples

> [!NOTE]
> This document covers the library's full API surface with working examples.
> Follow the section header links for complete API documentation on each class.

---

## High Level API

_Safe defaults, authentication built in, no footguns._

### [Seal](./aead.md#seal): one-shot authenticated encryption

One-shot AEAD over any `CipherSuite`. No instantiation, no `dispose()`. Pass the
cipher object, the key, and the plaintext.

```typescript
import { init, Seal, XChaCha20Cipher } from 'leviathan-crypto'
import { chacha20Wasm } from 'leviathan-crypto/chacha20/embedded'
import { sha2Wasm }     from 'leviathan-crypto/sha2/embedded'

await init({ chacha20: chacha20Wasm, sha2: sha2Wasm })

const key  = XChaCha20Cipher.keygen()
const blob = Seal.encrypt(XChaCha20Cipher, key, new TextEncoder().encode('Authenticated secret message.'))
const pt   = Seal.decrypt(XChaCha20Cipher, key, blob)  // throws on tamper

console.log(new TextDecoder().decode(pt))
// => "Authenticated secret message."
```

Works identically with `SerpentCipher`:

```typescript
import { init, Seal, SerpentCipher } from 'leviathan-crypto'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'
import { sha2Wasm }    from 'leviathan-crypto/sha2/embedded'

await init({ serpent: serpentWasm, sha2: sha2Wasm })

const key  = SerpentCipher.keygen()
const blob = Seal.encrypt(SerpentCipher, key, plaintext)
const pt   = Seal.decrypt(SerpentCipher, key, blob)
```

---

### [KyberSuite](./aead.md#kybersuite): post-quantum hybrid encryption

Wraps `MlKemBase` and a `CipherSuite` into a hybrid KEM+AEAD suite. The KEM
encapsulates a fresh shared secret on each encrypt. The inner cipher performs
the AEAD. The KEM ciphertext is prepended to the blob automatically.

```typescript
import { init, Seal, KyberSuite, MlKem768, XChaCha20Cipher } from 'leviathan-crypto'
import { kyberWasm }    from 'leviathan-crypto/kyber/embedded'
import { sha3Wasm }     from 'leviathan-crypto/sha3/embedded'
import { chacha20Wasm } from 'leviathan-crypto/chacha20/embedded'
import { sha2Wasm }     from 'leviathan-crypto/sha2/embedded'

await init({ kyber: kyberWasm, sha3: sha3Wasm, chacha20: chacha20Wasm, sha2: sha2Wasm })

const suite = KyberSuite(new MlKem768(), XChaCha20Cipher)
const { encapsulationKey: ek, decapsulationKey: dk } = suite.keygen()

// sender — encrypts with the public key
const blob = Seal.encrypt(suite, ek, plaintext)

// recipient — decrypts with the private key
const pt = Seal.decrypt(suite, dk, blob)
```

---

### [SealStream / OpenStream](./aead.md#sealstream): streaming encryption

For data arriving in chunks, such as network streams, file processors, or live feeds,
use `SealStream` and `OpenStream`. The cipher plugs in identically to `Seal`.

```typescript
import { init, SealStream, OpenStream, XChaCha20Cipher, randomBytes } from 'leviathan-crypto'
import { chacha20Wasm } from 'leviathan-crypto/chacha20/embedded'
import { sha2Wasm }     from 'leviathan-crypto/sha2/embedded'

await init({ chacha20: chacha20Wasm, sha2: sha2Wasm })

const key      = randomBytes(32)
const sealer   = new SealStream(XChaCha20Cipher, key, { chunkSize: 65536 })
const preamble = sealer.preamble  // send first

const ct0    = sealer.push(chunk0)
const ct1    = sealer.push(chunk1)
const ctFinal = sealer.finalize(lastChunk)

// recipient
const opener  = new OpenStream(XChaCha20Cipher, key, preamble)
const pt0     = opener.pull(ct0)
const pt1     = opener.pull(ct1)
const ptFinal = opener.finalize(ctFinal)
```

To use Serpent-256, swap the cipher object; everything else stays the same:

```typescript
import { init, SealStream, OpenStream, SerpentCipher, randomBytes } from 'leviathan-crypto'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'
import { sha2Wasm }    from 'leviathan-crypto/sha2/embedded'

await init({ serpent: serpentWasm, sha2: sha2Wasm })

const key      = randomBytes(32)
const sealer   = new SealStream(SerpentCipher, key, { chunkSize: 65536 })
const preamble = sealer.preamble

const ct0    = sealer.push(chunk0)
const ct1    = sealer.push(chunk1)
const ctLast = sealer.finalize(lastChunk)

const opener = new OpenStream(SerpentCipher, key, preamble)
const pt0    = opener.pull(ct0)
const pt1    = opener.pull(ct1)
const ptLast = opener.finalize(ctLast)
```

---

### [SealStreamPool](./aead.md#sealstreampool): parallel batch encryption

`SealStreamPool` distributes chunks across Web Workers. Same wire format as
`SealStream`. Drop-in for large files or batch workloads.

```typescript
import { init, SealStreamPool, XChaCha20Cipher, randomBytes } from 'leviathan-crypto'
import { chacha20Wasm } from 'leviathan-crypto/chacha20/embedded'
import { sha2Wasm }     from 'leviathan-crypto/sha2/embedded'

await init({ chacha20: chacha20Wasm, sha2: sha2Wasm })

const key  = randomBytes(32)
const pool = await SealStreamPool.create(XChaCha20Cipher, key, {
  wasm: chacha20Wasm, chunkSize: 65536,
})
const ciphertext = await pool.seal(plaintext)
const decrypted  = await pool.open(ciphertext)
pool.destroy()
```

---

### Post-quantum key encapsulation with ML-KEM

ML-KEM provides post-quantum key encapsulation. The sender encapsulates a
shared secret to the recipient's public encapsulation key. The recipient
recovers the same shared secret using their private decapsulation key.

```typescript
import { init, MlKem768 } from 'leviathan-crypto'
import { kyberWasm } from 'leviathan-crypto/kyber/embedded'
import { sha3Wasm }  from 'leviathan-crypto/sha3/embedded'

await init({ kyber: kyberWasm, sha3: sha3Wasm })

const kem = new MlKem768()

// keygen — once, store securely
const { encapsulationKey, decapsulationKey } = kem.keygen()

// sender — has only encapsulationKey
const { ciphertext, sharedSecret: senderSecret } = kem.encapsulate(encapsulationKey)

// recipient — has decapsulationKey
const recipientSecret = kem.decapsulate(decapsulationKey, ciphertext)

// senderSecret and recipientSecret are identical 32-byte values
// use as a symmetric key input: derive with HKDF or pass directly to KyberSuite
kem.dispose()
```

Hybrid X25519 + ML-KEM pattern: combine a classical X25519 shared secret with
an ML-KEM shared secret for defense in depth. Both must be broken simultaneously
for an attacker to succeed. (X25519 is not in this library. Use WebCrypto or a
dedicated library.)

```typescript
import { init, MlKem768, HKDF_SHA256 } from 'leviathan-crypto'
import { kyberWasm } from 'leviathan-crypto/kyber/embedded'
import { sha3Wasm }  from 'leviathan-crypto/sha3/embedded'
import { sha2Wasm }  from 'leviathan-crypto/sha2/embedded'

await init({ kyber: kyberWasm, sha3: sha3Wasm, sha2: sha2Wasm })

// x25519SharedSecret: 32 bytes from WebCrypto ECDH
const kem = new MlKem768()
const { encapsulationKey, decapsulationKey } = kem.keygen()
const { ciphertext, sharedSecret: kyberSecret } = kem.encapsulate(encapsulationKey)

const hkdf     = new HKDF_SHA256()
const combined = new Uint8Array(64)
combined.set(x25519SharedSecret, 0)
combined.set(kyberSecret, 32)

const hybridKey = hkdf.derive(combined, salt, info, 32)

kem.dispose()
hkdf.dispose()
```

Key validation before use (e.g. after deserializing from storage):

```typescript
const kem = new MlKem768()
const { encapsulationKey, decapsulationKey } = kem.keygen()

const ekValid = kem.checkEncapsulationKey(encapsulationKey)
const dkValid = kem.checkDecapsulationKey(decapsulationKey)

if (!ekValid || !dkValid) {
  throw new Error('Key validation failed — key may be corrupted')
}

kem.dispose()
```

---

### [SHA-256 hash + HMAC verify](./sha2.md)

Hash a message, then use HMAC to authenticate it. Always use
[`constantTimeEqual`](./utils.md#constanttimeequal) for tag comparison.

```typescript
import { init, SHA256, HMAC_SHA256, constantTimeEqual, randomBytes, bytesToHex, utf8ToBytes } from 'leviathan-crypto'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await init({ sha2: sha2Wasm })

// Hash
const sha    = new SHA256()
const digest = sha.hash(utf8ToBytes('Hello, world!'))
console.log(bytesToHex(digest))
// => "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3"
sha.dispose()

// HMAC: generate and verify
const key     = randomBytes(32)
const hmac    = new HMAC_SHA256()
const message = utf8ToBytes('Transfer $100 to Alice')
const tag     = hmac.hash(key, message)

// Always verify constant-time
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
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'
import { sha2Wasm }    from 'leviathan-crypto/sha2/embedded'

await init({ serpent: serpentWasm, sha2: sha2Wasm })

const rng   = await Fortuna.create()
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
> # Danger Zone: Raw primitives with no built-in authentication
>
> *The classes below give you direct access to unauthenticated cipher modes and
> low-level MAC and KDF primitives. They exist for protocol implementors and
> advanced use cases. If you are building general-purpose encryption, stop here
> and use [`Seal`](./aead.md#seal) with `SerpentCipher` or `XChaCha20Cipher` instead.*

### [SerpentCbc](./serpent.md): raw CBC mode

*Provides confidentiality only. An attacker can modify ciphertext without
detection. Pair with `HMAC_SHA256` using Encrypt-then-MAC.*

```typescript
import { init, SerpentCbc, randomBytes } from 'leviathan-crypto'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'

await init({ serpent: serpentWasm })

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
corresponding plaintext bit with no error. Pair with `HMAC_SHA256` using Encrypt-then-MAC.*

```typescript
import { init, SerpentCtr, randomBytes } from 'leviathan-crypto'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'

await init({ serpent: serpentWasm })

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
Identical plaintext blocks produce identical ciphertext. Use `Seal` with
`SerpentCipher` unless you are implementing a custom mode.*

```typescript
import { init, Serpent, randomBytes } from 'leviathan-crypto'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'

await init({ serpent: serpentWasm })

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
bit flips in plaintext with no error. Pair with `Poly1305` using Encrypt-then-MAC.*

```typescript
import { init, ChaCha20, randomBytes } from 'leviathan-crypto'
import { chacha20Wasm } from 'leviathan-crypto/chacha20/embedded'

await init({ chacha20: chacha20Wasm })

const key    = randomBytes(32)
const nonce  = randomBytes(12)  // 12-byte nonce for raw ChaCha20
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

*The key must never be reused across messages. Reuse allows an attacker to
recover `r` and forge arbitrary tags. The [AEAD classes](./aead.md) handle key derivation
automatically. Use them unless you have a specific reason not to.*

```typescript
import { init, Poly1305, randomBytes } from 'leviathan-crypto'
import { chacha20Wasm } from 'leviathan-crypto/chacha20/embedded'

await init({ chacha20: chacha20Wasm })

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

*RFC-faithful stateless primitive. The caller manages nonces. __Reusing a nonce
with the same key is catastrophic.__*

```typescript
import { init, XChaCha20Poly1305, randomBytes, utf8ToBytes, bytesToUtf8 } from 'leviathan-crypto'
import { chacha20Wasm } from 'leviathan-crypto/chacha20/embedded'

await init({ chacha20: chacha20Wasm })

const key   = randomBytes(32)
const nonce = randomBytes(24)  // caller must guarantee uniqueness per key
const aead  = new XChaCha20Poly1305()

const sealed    = aead.encrypt(key, nonce, utf8ToBytes('Hello, world!'))  // ct || tag(16)
const decrypted = aead.decrypt(key, nonce, sealed)                        // throws on tamper

console.log(bytesToUtf8(decrypted))  // => "Hello, world!"

aead.dispose()
```

---

### [ChaCha20Poly1305](./chacha20.md): stateless AEAD primitive (RFC 8439)

*12-byte nonce variant. Same caller-managed-nonce hazard as `XChaCha20Poly1305`.
The 12-byte nonce space makes random generation risky at scale.*

```typescript
import { init, ChaCha20Poly1305, randomBytes, utf8ToBytes, bytesToUtf8 } from 'leviathan-crypto'
import { chacha20Wasm } from 'leviathan-crypto/chacha20/embedded'

await init({ chacha20: chacha20Wasm })

const key   = randomBytes(32)
const nonce = randomBytes(12)  // 12-byte nonce: collision risk at ~2^32 messages
const aead  = new ChaCha20Poly1305()

const sealed    = aead.encrypt(key, nonce, utf8ToBytes('Hello, world!'))  // ct || tag(16)
const decrypted = aead.decrypt(key, nonce, sealed)

aead.dispose()
```

---

### [HKDF_SHA256](./sha2.md): manual key derivation

*Extract-then-expand. The `info` parameter is your domain separator: use
different values for different derived keys from the same root material.*

```typescript
import { init, HKDF_SHA256, randomBytes, utf8ToBytes, bytesToHex } from 'leviathan-crypto'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await init({ sha2: sha2Wasm })

const hkdf = new HKDF_SHA256()

const ikm  = randomBytes(32)                           // input keying material
const salt = randomBytes(32)                           // random, per-session
const info = utf8ToBytes('my-app-v1-encryption-key')   // domain separation

const derived = hkdf.derive(ikm, salt, info, 64)       // 64 bytes out
const encKey  = derived.subarray(0, 32)                // first 32: enc key
const macKey  = derived.subarray(32, 64)               // last 32: MAC key

console.log(bytesToHex(encKey))

hkdf.dispose()
```

---

### [SHAKE128 / SHAKE256](./sha3.md): XOF squeeze

*Extendable output functions: squeeze as many bytes as you need from a single
absorption. The capacity determines security, not the output length. SHAKE128
provides 128-bit security. SHAKE256 provides 256-bit security.*

```typescript
import { init, SHAKE256, randomBytes, bytesToHex } from 'leviathan-crypto'
import { sha3Wasm } from 'leviathan-crypto/sha3/embedded'

await init({ sha3: sha3Wasm })

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
> - [lexicon](./lexicon.md) — Glossary of cryptographic terms
> - [cdn](./cdn.md) — CDN usage: no bundler required
