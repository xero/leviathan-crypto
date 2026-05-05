<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### CipherSuite

The extension point for the streaming AEAD layer. `Seal`, `SealStream`, `OpenStream`, and `SealStreamPool` are all cipher-agnostic. You provide the cipher by passing a `CipherSuite` object at construction.

---

Four implementations are included: `SerpentCipher`, `XChaCha20Cipher`,
`AESGCMSIVCipher`, and `KyberSuite`. The first three are symmetric cipher
suites. `KyberSuite` wraps any of them with an ML-KEM layer for hybrid
post-quantum encryption.

---

## Symmetric implementations

|                   | `SerpentCipher`                | `XChaCha20Cipher`         | `AESGCMSIVCipher`             |
| ----------------- | ------------------------------ | ------------------------- | ----------------------------- |
| Cipher            | Serpent-256 CBC + HMAC-SHA-256 | XChaCha20-Poly1305        | AES-256-GCM-SIV (RFC 8452)    |
| `formatEnum`      | `0x02`                         | `0x03`                    | `0x04`                        |
| `hkdfInfo`        | `serpent-sealstream-v3`        | `xchacha20-sealstream-v3` | `aes-gcm-siv-sealstream-v3`   |
| `keySize`         | 32 bytes                       | 32 bytes                  | 32 bytes                      |
| `tagSize`         | 32 bytes                       | 16 bytes                  | 16 bytes                      |
| `commitmentSize`  | `0`                            | `32` (HtE)                | `32` (HtE)                    |
| `padded`          | `true` (PKCS7)                 | `false`                   | `false`                       |
| `wasmChunkSize`   | `65552`                        | `65536`                   | `65536`                       |
| `wasmModules`     | `['serpent', 'sha2']`          | `['chacha20', 'sha2']`    | `['aes', 'sha2']`             |
| Auth construction | Encrypt-then-MAC               | AEAD                      | AEAD (nonce-misuse-resistant) |

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
takes the 20-byte preamble header as part of its info string and emits
64 bytes: bytes 0..32 feed HChaCha20 subkey derivation, bytes 32..64
are a 32-byte key commitment that ends up in the preamble. The
commitment is verified before any chunk is processed and closes the
Invisible Salamanders attack surface (Poly1305 alone is not key
committing). The intermediate stream key is wiped immediately after
subkey derivation.

See [chacha20.md](./chacha20.md) for the full ChaCha20 primitive reference.

### AESGCMSIVCipher

```typescript
import { init, AESGCMSIVCipher } from 'leviathan-crypto'
import { aesWasm }  from 'leviathan-crypto/aes/embedded'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await init({ aes: aesWasm, sha2: sha2Wasm })

const key = AESGCMSIVCipher.keygen()  // 32 bytes
```

`AESGCMSIVCipher` uses AES-256-GCM-SIV (RFC 8452) AEAD per chunk —
nonce-misuse-resistant authenticated encryption with a 16-byte tag.
HKDF-SHA-256 takes the 20-byte preamble header as part of its info
string and emits 64 bytes: bytes 0..32 are the per-stream AES-GCM-SIV
key (no subkey-derivation step — AES-GCM-SIV's nonce is 12 bytes,
used directly per chunk; there is no HChaCha20 analog), bytes 32..64
are a 32-byte key commitment that ends up in the preamble. The
commitment is verified before any chunk is processed and closes the
Invisible Salamanders attack surface — AES-GCM-SIV's POLYVAL-based MAC
is not key-committing on its own (same posture as Poly1305).

The cipher suite is AES-256 only. The standalone `AESGCMSIV` primitive
class continues to support both AES-128 and AES-256 (RFC 8452 §6).

See [exports.md](./exports.md#aes) for the AES primitive reference and the AES export inventory.

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

| Suite                            | `formatEnum` | Preamble size |
| -------------------------------- | ------------ | ------------- |
| `MlKem512` + `XChaCha20Cipher`   | `0x13`       | 820 bytes     |
| `MlKem512` + `SerpentCipher`     | `0x12`       | 788 bytes     |
| `MlKem512` + `AESGCMSIVCipher`   | `0x14`       | 820 bytes     |
| `MlKem768` + `XChaCha20Cipher`   | `0x23`       | 1140 bytes    |
| `MlKem768` + `SerpentCipher`     | `0x22`       | 1108 bytes    |
| `MlKem768` + `AESGCMSIVCipher`   | `0x24`       | 1140 bytes    |
| `MlKem1024` + `XChaCha20Cipher`  | `0x33`       | 1620 bytes    |
| `MlKem1024` + `SerpentCipher`    | `0x32`       | 1588 bytes    |
| `MlKem1024` + `AESGCMSIVCipher`  | `0x34`       | 1620 bytes    |

XChaCha20 and AES-GCM-SIV hybrid suites carry a 32-byte commitment in
the preamble after the KEM ciphertext (header(20) + kemCt + commitment(32));
Serpent hybrid suites have no commitment field (header(20) + kemCt).
The AES-GCM-SIV preamble sizes match XChaCha20 because both have
`commitmentSize: 32`.

See [kyber.md](./kyber.md) for the full ML-KEM reference and key management guidance.

---

## Interface reference

`CipherSuite` is an interface, not a class. `SerpentCipher` and `XChaCha20Cipher`
are plain `const` objects. You can implement your own by satisfying the interface.

### Fields

| Field           | Type                  | Description                                                              |
| --------------- | --------------------- | ------------------------------------------------------------------------ |
| `formatEnum`    | `number`              | Wire format ID. Bits 0-3 cipher nibble (0x2=serpent, 0x3=xchacha20, 0x4=aes-gcm-siv); bits 4-5 KEM selector (0x00=none, 0x10=ML-KEM-512, 0x20=ML-KEM-768, 0x30=ML-KEM-1024); bit 6 reserved; max `0x3f`. |
| `formatName`    | `string`              | Human-readable label, e.g. `'xchacha20'`, `'serpent'`. Used in hybrid suite names (`'mlkem768+xchacha20'`). |
| `hkdfInfo`      | `string`              | HKDF info string for domain separation between cipher suites.            |
| `keySize`       | `number`              | Required master key length in bytes. For KEM suites this is the encapsulation key (ek) size. |
| `decKeySize?`   | `number \| undefined` | Decryption key size in bytes. Absent for symmetric suites (defaults to `keySize`). For KEM suites this is the decapsulation key (dk) size. |
| `kemCtSize`     | `number`              | KEM ciphertext size in bytes. `0` for symmetric suites; set to the KEM ciphertext length for hybrid suites. |
| `tagSize`       | `number`              | Authentication tag size in bytes per chunk.                              |
| `padded`        | `boolean`             | Whether ciphertext includes block padding. Affects pool chunk splitting. |
| `wasmChunkSize` | `number`              | WASM buffer capacity for one padded chunk. Pool validates `paddedFull ≤ wasmChunkSize` at creation for padded ciphers. Must match the `CHUNK_SIZE` constant in the cipher's WASM module. |
| `wasmModules`   | `readonly string[]`   | WASM modules this suite requires.                                        |

### Methods

| Method                                       | Description                                                 |
| -------------------------------------------- | ----------------------------------------------------------- |
| `deriveKeys(masterKey, nonce, kemCt?)`       | HKDF key derivation. `kemCt` is the KEM ciphertext — present only for hybrid suites, absent for symmetric. Returns opaque `DerivedKeys`. |
| `sealChunk(keys, counterNonce, chunk, aad?)` | Encrypt one chunk. Returns ciphertext with tag appended.    |
| `openChunk(keys, counterNonce, chunk, aad?)` | Decrypt one chunk. Throws `AuthenticationError` on failure. |
| `wipeKeys(keys)`                             | Zero all derived key material. Called after `finalize()`.   |
| `createPoolWorker()`                         | Create a Web Worker for pool use. Default implementations spawn a classic worker from a blob URL over an IIFE source bundled at lib build time. Override via spread (`{ ...XChaCha20Cipher, createPoolWorker: () => new Worker(myUrl) }`) for strict-CSP environments that disallow `blob:` in `worker-src`. |

### Implementing a custom CipherSuite

Your `formatEnum` must not conflict with the built-in values (`0x02`, `0x03`,
`0x04`, `0x12`, `0x13`, `0x14`, `0x22`, `0x23`, `0x24`, `0x32`, `0x33`,
`0x34`). Bit 6 of header byte 0 is reserved (`readHeader` rejects it); bit
7 is `FLAG_FRAMED` and is set by the framing layer. The
`hkdfInfo` string must be unique to your cipher to prevent key reuse across suites.
`wipeKeys` must zero every byte of derived key material — the stream layer calls
it unconditionally after finalize.

---

## Cross-References

| Document | Description |
| -------- | ----------- |
| [index](./README.md) | Project Documentation index |
| [architecture](./architecture.md) | architecture overview, module relationships, buffer layouts, and build pipeline |
| [lexicon](./lexicon.md) | Glossary of cryptographic terms |
| [authenticated encryption](./aead.md) | `Seal`, `SealStream`, `OpenStream`, `SealStreamPool` |
| [serpent](./serpent.md) | Serpent-256 TypeScript API and raw primitives |
| [chacha20](./chacha20.md) | ChaCha20 TypeScript API and raw primitives |
| [kyber](./kyber.md) | ML-KEM key encapsulation and `KyberSuite` |
| [types](./types.md) | TypeScript interfaces |

