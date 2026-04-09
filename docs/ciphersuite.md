# CipherSuite

> [!NOTE]
> The extension point for the streaming AEAD layer. `Seal`, `SealStream`,
> `OpenStream`, and `SealStreamPool` are all cipher-agnostic. You provide
> the cipher by passing a `CipherSuite` object at construction.

Three implementations are included: `SerpentCipher`, `XChaCha20Cipher`, and
`KyberSuite`. The first two are symmetric cipher suites. `KyberSuite` wraps
either of them with an ML-KEM layer for hybrid post-quantum encryption.

---

## Symmetric implementations

|                   | `SerpentCipher`                | `XChaCha20Cipher`         |
| ----------------- | ------------------------------ | ------------------------- |
| Cipher            | Serpent-256 CBC + HMAC-SHA-256 | XChaCha20-Poly1305        |
| `formatEnum`      | `0x02`                         | `0x01`                    |
| `hkdfInfo`        | `serpent-sealstream-v2`        | `xchacha20-sealstream-v2` |
| `keySize`         | 32 bytes                       | 32 bytes                  |
| `tagSize`         | 32 bytes                       | 16 bytes                  |
| `padded`          | `true` (PKCS7)                 | `false`                   |
| `wasmModules`     | `['serpent', 'sha2']`          | `['chacha20', 'sha2']`    |
| Auth construction | Encrypt-then-MAC               | AEAD                      |

### SerpentCipher

```typescript
import { init, SerpentCipher } from 'leviathan-crypto'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'
import { sha2Wasm }    from 'leviathan-crypto/sha2/embedded'

await init({ serpent: serpentWasm, sha2: sha2Wasm })

const key = SerpentCipher.keygen()  // 32 bytes
```

`SerpentCipher` uses Encrypt-then-MAC: Serpent-256-CBC for encryption and
HMAC-SHA-256 for authentication. HKDF-SHA-256 derives three keys from the
master key and stream nonce: an encryption key, a MAC key, and an IV key.
The CBC IV is derived deterministically per chunk and never transmitted.

See [serpent.md](./serpent.md) for the full Serpent-256 primitive reference.

### XChaCha20Cipher

```typescript
import { init, XChaCha20Cipher } from 'leviathan-crypto'
import { chacha20Wasm } from 'leviathan-crypto/chacha20/embedded'
import { sha2Wasm }     from 'leviathan-crypto/sha2/embedded'

await init({ chacha20: chacha20Wasm, sha2: sha2Wasm })

const key = XChaCha20Cipher.keygen()  // 32 bytes
```

`XChaCha20Cipher` uses XChaCha20-Poly1305 AEAD per chunk. HKDF-SHA-256
derives a stream key, then HChaCha20 derives a per-chunk subkey. The
intermediate stream key is wiped immediately after derivation.

See [chacha20.md](./chacha20.md) for the full ChaCha20 primitive reference.

---

## KyberSuite

`KyberSuite` is a factory that wraps a `MlKemBase` instance and an inner
`CipherSuite` into a hybrid KEM+AEAD suite. The result satisfies the
`CipherSuite` interface and plugs into `Seal`, `SealStream`, `OpenStream`,
and `SealStreamPool` identically to the symmetric suites.

```typescript
import { KyberSuite, MlKem768 } from 'leviathan-crypto/kyber'
import { XChaCha20Cipher }      from 'leviathan-crypto/chacha20'

const suite = KyberSuite(new MlKem768(), XChaCha20Cipher)
const { encapsulationKey: ek, decapsulationKey: dk } = suite.keygen()
```

On encrypt, ML-KEM encapsulates a fresh shared secret. HKDF binds the KEM
ciphertext into key derivation. On decrypt, the KEM ciphertext is recovered
from the preamble and decapsulated. The inner cipher runs on the derived key
material. Neither party ever transmits the shared secret.

`formatEnum` encodes both the KEM parameter set and inner cipher in a single
byte. This allows `OpenStream` to infer the full suite from the preamble alone.

| Suite                           | `formatEnum` | Preamble size |
| ------------------------------- | ------------ | ------------- |
| `MlKem512` + `XChaCha20Cipher`  | `0x11`       | 788 bytes     |
| `MlKem512` + `SerpentCipher`    | `0x12`       | 788 bytes     |
| `MlKem768` + `XChaCha20Cipher`  | `0x21`       | 1108 bytes    |
| `MlKem768` + `SerpentCipher`    | `0x22`       | 1108 bytes    |
| `MlKem1024` + `XChaCha20Cipher` | `0x31`       | 1588 bytes    |
| `MlKem1024` + `SerpentCipher`   | `0x32`       | 1588 bytes    |

See [kyber.md](./kyber.md) for the full ML-KEM reference and key management guidance.

---

## Interface reference

`CipherSuite` is an interface, not a class. `SerpentCipher` and `XChaCha20Cipher`
are plain `const` objects. You can implement your own by satisfying the interface.

### Fields

| Field         | Type                | Description                                                              |
| ------------- | ------------------- | ------------------------------------------------------------------------ |
| `formatEnum`  | `number`            | Wire format ID. Bits 0-5 of header byte 0. Max `0x3f`. Bit 6 reserved.   |
| `hkdfInfo`    | `string`            | HKDF info string for domain separation between cipher suites.            |
| `keySize`     | `number`            | Required master key length in bytes.                                     |
| `tagSize`     | `number`            | Authentication tag size in bytes per chunk.                              |
| `padded`      | `boolean`           | Whether ciphertext includes block padding. Affects pool chunk splitting. |
| `wasmModules` | `readonly string[]` | WASM modules this suite requires.                                        |

### Methods

| Method                                       | Description                                                 |
| -------------------------------------------- | ----------------------------------------------------------- |
| `deriveKeys(masterKey, nonce)`               | HKDF key derivation. Returns opaque `DerivedKeys`.          |
| `sealChunk(keys, counterNonce, chunk, aad?)` | Encrypt one chunk. Returns ciphertext with tag appended.    |
| `openChunk(keys, counterNonce, chunk, aad?)` | Decrypt one chunk. Throws `AuthenticationError` on failure. |
| `wipeKeys(keys)`                             | Zero all derived key material. Called after `finalize()`.   |
| `createPoolWorker()`                         | Create a Web Worker for pool use.                           |

### Implementing a custom CipherSuite

Your `formatEnum` must not conflict with the built-in values (`0x01`, `0x02`,
`0x11` through `0x32`). Bits 6 and 7 of header byte 0 are reserved. The
`hkdfInfo` string must be unique to your cipher to prevent key reuse across suites.
`wipeKeys` must zero every byte of derived key material — the stream layer calls
it unconditionally after finalize.

---

> ## Cross-References
>
> - [index](./README.md) — Project Documentation index
> - [architecture](./architecture.md) — architecture overview, module relationships, buffer layouts, and build pipeline
> - [lexicon](./lexicon.md) — Glossary of cryptographic terms
> - [authenticated encryption](./aead.md) — `Seal`, `SealStream`, `OpenStream`, `SealStreamPool`
> - [serpent](./serpent.md) — Serpent-256 TypeScript API and raw primitives
> - [chacha20](./chacha20.md) — ChaCha20 TypeScript API and raw primitives
> - [kyber](./kyber.md) — ML-KEM key encapsulation and `KyberSuite`
> - [types](./types.md) — TypeScript interfaces
