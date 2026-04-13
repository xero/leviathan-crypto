# Examples

> [!NOTE]
> This document covers the library's full API surface with working examples.
> Follow the section header links for complete API documentation on each class.

---

## High Level API

It provides safe defaults with authentication built in.

### [Seal](./aead.md#seal): one-shot authenticated encryption

Use `Seal` for one-shot AEAD with any `CipherSuite`. Pass the cipher, the key, and the plaintext; no instantiation or `dispose()` call is needed.

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

It works identically with `SerpentCipher`:

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

`KyberSuite` wraps an ML-KEM instance and a `CipherSuite` into a hybrid KEM+AEAD suite. Each call to `encrypt` creates a fresh shared secret via the KEM, then the inner cipher performs AEAD. The KEM ciphertext is prepended to the blob automatically.

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

`SealStreamPool` distributes chunks across Web Workers. It produces the same wire format as `SealStream` and works as a drop-in for large files or batch workloads.

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

To combine classical and post-quantum security, pair an X25519 shared secret with an ML-KEM shared secret. Both must be broken simultaneously for an attacker to succeed. X25519 is not in this library; use WebCrypto or a dedicated library for it.

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

To validate keys before use, for example after deserializing from storage:

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

### [Post-quantum forward-secret messaging](./ratchet.md)

These five primitives cover building a Signal-like session on top of ML-KEM. Each example shows the API shape of one export. For the full Alice-and-Bob
round trip with message encryption, epoch transitions, and transport
layout, see the [usage example](./ratchet.md#usage-example) and
[bilateral chain exchange](./ratchet.md#bilateral-chain-exchange)
sections of the ratchet guide.

**`ratchetInit(sharedSecret, context?)`** — derive the initial root key
and both chain keys from a shared secret established out of band.

```typescript
import { init, ratchetInit } from 'leviathan-crypto'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await init({ sha2: sha2Wasm })

// sharedSecret: 32 bytes from a prior KEM or key-agreement protocol
const { rootKey, sendChainKey, recvChainKey } = ratchetInit(sharedSecret)
```

**`KDFChain`** — stateful per-message KDF. Each `step()` advances the
chain and returns a single-use 32-byte message key. `stepWithCounter()`
returns the key and the post-step counter atomically.

```typescript
import { KDFChain } from 'leviathan-crypto'

const chain = new KDFChain(sendChainKey)

const msgKey1 = chain.step()                     // counter 1
const { key: msgKey2, counter } = chain.stepWithCounter()  // counter 2

// Use each msgKey exactly once to encrypt, then discard it.
chain.dispose()
```

**`kemRatchetEncap` / `kemRatchetDecap`** — advance the root key with a
fresh ML-KEM encapsulation. Both sides arrive at the same pair of chain
keys; Alice's send chain is Bob's receive chain and vice versa.

```typescript
import {
  init,
  MlKem768,
  kemRatchetEncap,
  kemRatchetDecap,
  constantTimeEqual,
} from 'leviathan-crypto'

await init({ sha2: sha2Wasm, kyber: kyberWasm, sha3: sha3Wasm })

const kem = new MlKem768()

// Bob publishes his ek; Alice receives it. Both sides share a 32-byte rootKey.
const { encapsulationKey: bobEk, decapsulationKey: bobDk } = kem.keygen()
const rootKey = /* 32 bytes, from a prior ratchetInit or previous KEM step */

// Alice: encap side
const alice = kemRatchetEncap(kem, rootKey, bobEk)
// alice.kemCt goes on the wire; alice.sendChainKey / recvChainKey stay local

// Bob: decap side (receives kemCt from Alice)
const bob = kemRatchetDecap(kem, rootKey, bobDk, alice.kemCt, bobEk)

console.log(constantTimeEqual(alice.sendChainKey, bob.recvChainKey))  // => true
console.log(constantTimeEqual(alice.recvChainKey, bob.sendChainKey))  // => true

// Both sides now feed these chain keys into KDFChain for per-message keys.
kem.dispose()
```

**`SkippedKeyStore`** — caches message keys for out-of-order delivery.
`resolve()` returns a `ResolveHandle`; settle with `commit()` on
successful decrypt (wipes the key) or `rollback()` on auth failure
(preserves the key for a legitimate retry at the same counter).

```typescript
import { SkippedKeyStore } from 'leviathan-crypto'

const store = new SkippedKeyStore({ maxCacheSize: 100, maxSkipPerResolve: 50 })

const handle = store.resolve(chain, incomingCounter)
try {
  const plaintext = Seal.decrypt(cipher, handle.key, ciphertext)
  handle.commit()        // success — key is wiped
  return plaintext
} catch (e) {
  handle.rollback()      // auth failed — key returns to the store
  throw e
}
```

**`RatchetKeypair`** — single-use ek/dk wrapper for the decap side. The
dk is wiped automatically after the one permitted `decap` call.

```typescript
import { RatchetKeypair, MlKem768 } from 'leviathan-crypto'

const kem     = new MlKem768()
const keypair = new RatchetKeypair(kem)

// Share keypair.ek with the encap side, then receive kemCt back
const { sendChainKey, recvChainKey } = keypair.decap(kem, rootKey, kemCt)

keypair.dispose()   // idempotent; safe to call after decap()
kem.dispose()
```

For the full round-trip story covering message counters, epoch
transitions, and how these primitives compose into a complete session,
see the [ratchet guide](./ratchet.md).

---

### Hashing + HMAC verify

Hash a message, then use HMAC to authenticate it. Always use
[`constantTimeEqual`](./utils.md#constanttimeequal) for tag comparison.
See [sha2.md](./sha2.md) and [sha3.md](./sha3.md) for the full per-class
reference.

```typescript
import {
  init,
  SHA256,
  HMAC_SHA256,
  constantTimeEqual,
  randomBytes,
  bytesToHex,
  utf8ToBytes,
} from 'leviathan-crypto'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await init({
  sha2: sha2Wasm,
})

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

**Other hash algorithms follow the same shape.** Swap the class name, the
init module, and expect a different digest size. The `hash(msg)` and
`dispose()` signatures are identical across every class.

| Class | Init | Digest size |
|---|---|---|
| `SHA256` | `sha2` | 32 bytes |
| `SHA384` | `sha2` | 48 bytes |
| `SHA512` | `sha2` | 64 bytes |
| `SHA3_224` | `sha3` | 28 bytes |
| `SHA3_256` | `sha3` | 32 bytes |
| `SHA3_384` | `sha3` | 48 bytes |
| `SHA3_512` | `sha3` | 64 bytes |

Example: to compute a SHA3-512 digest instead of SHA-256, change the
imports, the class name, and add `sha3` to the init call. The digest
comes back 64 bytes long; everything else stays the same.

```diff
 import {
   init,
-  SHA256,
+  SHA3_512,
   HMAC_SHA256,
   constantTimeEqual,
   randomBytes,
   bytesToHex,
   utf8ToBytes,
 } from 'leviathan-crypto'
-import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'
+import { sha3Wasm } from 'leviathan-crypto/sha3/embedded'

 await init({
   sha2: sha2Wasm,
+  sha3: sha3Wasm,
 })

-const sha    = new SHA256()
+const sha    = new SHA3_512()
 const digest = sha.hash(utf8ToBytes('Hello, world!'))
 console.log(bytesToHex(digest))
-// => "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3"
+// => "8e47f1185ffd014d238fabd02a1a32defe698cbf38c037a90e3c0a0a32370fb52cbd641250508502295fcabcbf676c09470b27443868c8e5f70e26dc337288af"
```

HMAC variants follow the same pattern. `HMAC_SHA256`, `HMAC_SHA384`, and
`HMAC_SHA512` all expose `hash(key, message)` and `dispose()` with matching
tag sizes.

---

### [Fortuna CSPRNG](./fortuna.md)

`Fortuna` provides cryptographically secure random bytes with forward secrecy and 32 entropy pools. Pick a `Generator` (cipher PRF) and a `HashFn` (accumulator and reseed key derivation) at create time.

#### Minimum bundle: ChaCha20 + SHA-256

```typescript
import { init, Fortuna } from 'leviathan-crypto'
import { ChaCha20Generator } from 'leviathan-crypto/chacha20'
import { SHA256Hash } from 'leviathan-crypto/sha2'
import { chacha20Wasm } from 'leviathan-crypto/chacha20/embedded'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await init({ chacha20: chacha20Wasm, sha2: sha2Wasm })

const rng   = await Fortuna.create({ generator: ChaCha20Generator, hash: SHA256Hash })
const key   = rng.get(32)
const nonce = rng.get(24)
rng.stop()
```

#### Original Fortuna pair: Serpent + SHA-256

```typescript
import { init, Fortuna } from 'leviathan-crypto'
import { SerpentGenerator } from 'leviathan-crypto/serpent'
import { SHA256Hash } from 'leviathan-crypto/sha2'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await init({ serpent: serpentWasm, sha2: sha2Wasm })

const rng = await Fortuna.create({ generator: SerpentGenerator, hash: SHA256Hash })
const key = rng.get(32)
rng.stop()
```

#### Modern combination: ChaCha20 + SHA3-256

```typescript
import { init, Fortuna } from 'leviathan-crypto'
import { ChaCha20Generator } from 'leviathan-crypto/chacha20'
import { SHA3_256Hash } from 'leviathan-crypto/sha3'
import { chacha20Wasm } from 'leviathan-crypto/chacha20/embedded'
import { sha3Wasm } from 'leviathan-crypto/sha3/embedded'

await init({ chacha20: chacha20Wasm, sha3: sha3Wasm })

const rng   = await Fortuna.create({ generator: ChaCha20Generator, hash: SHA3_256Hash })
const token = rng.get(16)
rng.stop()
```

---

### [Utilities](./utils.md)

None of these utilities require `init()`.

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


## Cross-References

| Document | Description |
| -------- | ----------- |
| [index](./README.md) | Project Documentation index |
| [architecture](./architecture.md) | architecture overview, module relationships, buffer layouts, and build pipeline |
| [lexicon](./lexicon.md) | Glossary of cryptographic terms |
| [cdn](./cdn.md) | CDN usage: no bundler required |

