<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### CipherSuite

The extension point for the streaming AEAD layer. `Seal`, `SealStream`, `OpenStream`, and `SealStreamPool` are all cipher-agnostic. You provide the cipher by passing a `CipherSuite` object at construction.

> ### Table of Contents
> - [Module Init](#module-init)
> - [Security Notes](#security-notes)
> - [Symmetric implementations](#symmetric-implementations)
>   - [SerpentCipher](#serpentcipher)
>   - [XChaCha20Cipher](#xchacha20cipher)
>   - [AESGCMSIVCipher](#aesgcmsivcipher)
> - [KyberSuite](#kybersuite)
> - [Interface reference](#interface-reference)
> - [Per-cipher contract tests](#per-cipher-contract-tests)
> - [Cross-References](#cross-references)

---

Four implementations are included: `SerpentCipher`, `XChaCha20Cipher`,
`AESGCMSIVCipher`, and `KyberSuite`. The first three are symmetric cipher
suites. `KyberSuite` wraps any of them with an ML-KEM layer for hybrid
post-quantum encryption.

---

## Module Init

Each `CipherSuite` implementation requires its underlying cipher module plus `sha2` for HKDF-SHA-256 key derivation. `KyberSuite` additionally requires `sha3` for the ML-KEM sponge.

| Suite | `init({ ... })` keys |
|---|---|
| `SerpentCipher` | `serpent`, `sha2` |
| `XChaCha20Cipher` | `chacha20`, `sha2` |
| `AESGCMSIVCipher` | `aes`, `sha2` |
| `KyberSuite(MlKem*, inner)` | `kyber`, `sha3`, plus the inner suite's modules |

See [init.md](./init.md) for `WasmSource` types and the per-module init functions.

---

## Security Notes

> [!IMPORTANT]
> **All four shipped suites are authenticated.** `SerpentCipher` uses Encrypt-then-MAC over Serpent-256-CBC + HMAC-SHA-256. `XChaCha20Cipher` uses XChaCha20-Poly1305 AEAD. `AESGCMSIVCipher` uses AES-256-GCM-SIV nonce-misuse-resistant AEAD. `KyberSuite` inherits the inner suite's authentication.

> [!IMPORTANT]
> **Key commitment closes the Invisible Salamanders surface.** `XChaCha20Cipher` and `AESGCMSIVCipher` carry a 32-byte commitment in the preamble because Poly1305 and POLYVAL are not key-committing on their own. `SerpentCipher` uses HMAC-SHA-256 which is key-committing by construction and ships with `commitmentSize: 0`. Don't strip the commitment field or skip its verification.

> [!CAUTION]
> **Custom CipherSuite implementations must use a unique `hkdfInfo` string.** The stream layer derives per-stream keys via `HKDF-SHA-256(masterKey, info=hkdfInfo)`. Two suites sharing the same `hkdfInfo` produce identical keys from the same master key, breaking cross-suite isolation. `wipeKeys` must zero every byte of derived key material; the stream layer calls it unconditionally after `finalize()`.

> [!IMPORTANT]
> **`formatEnum` reserved values must not collide.** Built-in allocations: `0x02`, `0x03`, `0x04`, `0x12`, `0x13`, `0x14`, `0x22`, `0x23`, `0x24`, `0x32`, `0x33`, `0x34`. Bit 6 of header byte 0 is reserved (`readHeader` rejects it); bit 7 is `FLAG_FRAMED`, set by the framing layer.

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

`AESGCMSIVCipher` uses AES-256-GCM-SIV (RFC 8452) AEAD per chunk,
nonce-misuse-resistant authenticated encryption with a 16-byte tag.
HKDF-SHA-256 takes the 20-byte preamble header as part of its info
string and emits 64 bytes: bytes 0..32 are the per-stream AES-GCM-SIV
key (no subkey-derivation step, AES-GCM-SIV's nonce is 12 bytes,
used directly per chunk; there is no HChaCha20 analog), bytes 32..64
are a 32-byte key commitment that ends up in the preamble. The
commitment is verified before any chunk is processed and closes the
Invisible Salamanders attack surface, AES-GCM-SIV's POLYVAL-based MAC
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
| `deriveKeys(masterKey, nonce, kemCt?)`       | HKDF key derivation. `kemCt` is the KEM ciphertext, present only for hybrid suites, absent for symmetric. Returns opaque `DerivedKeys`. |
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
`wipeKeys` must zero every byte of derived key material, the stream layer calls
it unconditionally after finalize.

`CipherSuite` is the public-surface contract. The shipped implementations live
in [src/ts/serpent/cipher-suite.ts](../src/ts/serpent/cipher-suite.ts),
[src/ts/chacha20/cipher-suite.ts](../src/ts/chacha20/cipher-suite.ts), and
[src/ts/aes/cipher-suite.ts](../src/ts/aes/cipher-suite.ts). Read one of them
before writing your own. The examples below show the three patterns a
consumer is most likely to need.

#### Symmetric AEAD skeleton

A custom symmetric suite reduces to wiring an AEAD primitive into the four
methods. The shape is a plain `const` object that satisfies `CipherSuite`. The
example below outlines a hypothetical AES-256-OCB3 suite (not shipped); replace
the `ocb3Encrypt` / `ocb3Decrypt` placeholder calls with your primitive's
bindings.

```typescript
import { HKDF_SHA256, wipe, randomBytes, concat } from 'leviathan-crypto'
import type { CipherSuite, DerivedKeys } from 'leviathan-crypto'

const INFO = new TextEncoder().encode('aes-ocb3-customstream-v1')

export const AesOcb3Cipher: CipherSuite & { keygen(): Uint8Array } = {
  formatEnum:    0x05,                     // outside the reserved range
  formatName:    'aes-ocb3',
  hkdfInfo:      'aes-ocb3-customstream-v1',
  keySize:       32,
  kemCtSize:     0,
  commitmentSize: 32,                      // 0 only if the AEAD is key-committing on its own
  tagSize:       16,
  padded:        false,
  wasmChunkSize: 65536,                    // must match the WASM module's CHUNK_SIZE constant
  wasmModules:   ['aes', 'sha2'],

  keygen(): Uint8Array {
    return randomBytes(32)
  },

  deriveKeys(masterKey, nonce, _kemCt, header): DerivedKeys {
    if (!header || header.length !== 20)
      throw new Error('AesOcb3Cipher.deriveKeys: header binding required')

    const hkdf = new HKDF_SHA256()
    let okm: Uint8Array
    try {
      // INFO || header binds formatEnum, framed flag, nonce, chunkSize into the KDF.
      okm = hkdf.derive(masterKey, nonce, concat(INFO, header), 64)
    } finally {
      hkdf.dispose()
    }

    const bytes      = okm.slice(0,  32)    // per-stream AEAD key
    const commitment = okm.slice(32, 64)    // key commitment for the preamble
    wipe(okm)
    return { bytes, commitment }
  },

  sealChunk(keys, counterNonce, chunk, aad) {
    // call your AEAD encrypt; return ciphertext || 16-byte tag
    return ocb3Encrypt(keys.bytes, counterNonce, chunk, aad ?? new Uint8Array(0))
  },

  openChunk(keys, counterNonce, chunk, aad) {
    if (chunk.length < 16)
      throw new RangeError(`chunk too short for tag (got ${chunk.length})`)
    // call your AEAD decrypt; throw AuthenticationError on tag mismatch
    return ocb3Decrypt(keys.bytes, counterNonce, chunk, aad ?? new Uint8Array(0))
  },

  wipeKeys(keys) {
    wipe(keys.bytes)
  },

  createPoolWorker(): Worker {
    // see docs/architecture.md#build-pipeline for the IIFE spawn pattern
    const blob = new Blob([WORKER_SOURCE], { type: 'application/javascript' })
    const url  = URL.createObjectURL(blob)
    const w    = new Worker(url)
    setTimeout(() => URL.revokeObjectURL(url), 0)
    return w
  },
}
```

What the skeleton is doing:

**Commitment field.** Any AEAD whose MAC is not key-committing (Poly1305,
POLYVAL, OCB3) carries a 32-byte HKDF-derived commitment in the preamble.
Set `commitmentSize: 0` only when the construction is key-committing by
itself (HMAC, KMAC).

**Header binding.** Concatenating the 20-byte preamble header into HKDF
info binds `formatEnum`, the framed flag, the stream nonce, and `chunkSize`
into key derivation. Header tampering produces different keys and AEAD
fails on the first chunk.

**Wipe discipline.** `wipe(okm)` zeros both halves before return; the
commitment is safe because `slice` returns independent backing. The stream
layer calls `wipeKeys` unconditionally after `finalize()`.

**`wasmChunkSize`.** Must equal the underlying WASM module's `CHUNK_SIZE`
constant. For padded ciphers, the pool validates `paddedFull <= wasmChunkSize`
at construction.

#### Spread-override variant

When you only need to change one behaviour (most often `createPoolWorker`
for strict-CSP environments that disallow `blob:` URLs in `worker-src`),
use the spread pattern. The result is still a valid `CipherSuite`:

```typescript
import { XChaCha20Cipher } from 'leviathan-crypto'
import type { CipherSuite } from 'leviathan-crypto'

export const CspXChaCha20Cipher: CipherSuite = {
  ...XChaCha20Cipher,
  createPoolWorker: () => new Worker(
    new URL('./workers/xchacha20-pool-worker.js', import.meta.url),
    { type: 'classic' },
  ),
}
```

Do not change `formatEnum`, `hkdfInfo`, or any of the size fields when
wrapping. Doing so produces a wire format that no `OpenStream` will accept
and breaks the implicit contract that two parties using the same
`formatName` interop.

#### Hybrid KEM wrapper

`KyberSuite` shows the pattern for wrapping a KEM around any inner
`CipherSuite`. A custom KEM (HPKE, NTRU, a future PQ family) plugs in the
same way: encapsulate on the encrypt path, decapsulate on the decrypt path,
feed the shared secret through HKDF, then delegate `sealChunk` / `openChunk`
to the inner suite.

```typescript
import { HKDF_SHA256, concat } from 'leviathan-crypto'
import type { CipherSuite, DerivedKeys } from 'leviathan-crypto'

interface MyKem {
  readonly ekBytes: number
  readonly dkBytes: number
  readonly ctBytes: number
  encapsulate(ek: Uint8Array): { sharedSecret: Uint8Array; ciphertext: Uint8Array }
  decapsulate(dk: Uint8Array, ct: Uint8Array): Uint8Array
  keygen(): { encapsulationKey: Uint8Array; decapsulationKey: Uint8Array }
}

export function MyKemSuite(
  kem: MyKem,
  inner: CipherSuite,
): CipherSuite & { keygen(): ReturnType<MyKem['keygen']> } {
  const info = new TextEncoder().encode(inner.hkdfInfo)

  return {
    formatEnum:    0x40 | inner.formatEnum,   // pick a free KEM nibble (bits 4-5)
    formatName:    `mykem+${inner.formatName}`,
    hkdfInfo:      inner.hkdfInfo,
    keySize:       kem.ekBytes,               // encrypt path uses the encapsulation key
    decKeySize:    kem.dkBytes,               // decrypt path uses the decapsulation key
    kemCtSize:     kem.ctBytes,
    commitmentSize: inner.commitmentSize,
    tagSize:       inner.tagSize,
    padded:        inner.padded,
    wasmChunkSize: inner.wasmChunkSize,
    wasmModules:   [...inner.wasmModules, 'mykem'],

    deriveKeys(key, nonce, kemCt, header): DerivedKeys {
      let sharedSecret: Uint8Array
      let outKemCt: Uint8Array | undefined
      let ctForInfo: Uint8Array

      if (kemCt === undefined) {
        // encrypt path: key is the encapsulation key, emit a fresh ct
        const r = kem.encapsulate(key)
        sharedSecret = r.sharedSecret
        outKemCt     = r.ciphertext
        ctForInfo    = r.ciphertext
      } else {
        // decrypt path: key is the decapsulation key, recover ss from ct
        sharedSecret = kem.decapsulate(key, kemCt)
        ctForInfo    = kemCt
      }

      // Bind the KEM ciphertext into HKDF info (defense in depth).
      const hkdf    = new HKDF_SHA256()
      const derived = hkdf.derive(sharedSecret, nonce, concat(info, ctForInfo), inner.keySize)
      hkdf.dispose()
      sharedSecret.fill(0)

      // Delegate symmetric key derivation to the inner suite; forward the
      // header so suites that header-bind (XChaCha20, AES-GCM-SIV) see it.
      const innerKeys = inner.deriveKeys(derived, nonce, undefined, header)
      derived.fill(0)

      if (!outKemCt) return innerKeys
      return innerKeys.commitment
        ? { bytes: innerKeys.bytes, kemCiphertext: outKemCt, commitment: innerKeys.commitment }
        : { bytes: innerKeys.bytes, kemCiphertext: outKemCt }
    },

    sealChunk:        inner.sealChunk.bind(inner),
    openChunk:        inner.openChunk.bind(inner),
    wipeKeys:         inner.wipeKeys.bind(inner),
    createPoolWorker: inner.createPoolWorker.bind(inner),

    keygen() {
      return kem.keygen()
    },
  }
}
```

A few points specific to the hybrid path:

**Asymmetric key sizes.** `keySize` is the encapsulation-key length, used
by `SealStream`. `decKeySize` is the decapsulation-key length, used by
`OpenStream`. Symmetric suites omit `decKeySize` and the stream layer
defaults it to `keySize`.

**KEM ciphertext in the preamble.** The wire-format preamble is
`header(20) || kemCt || commitment?`. `deriveKeys` returns `kemCiphertext`
on the encrypt path so the stream layer can write it into the preamble; on
the decrypt path the stream layer pulls it back out and passes it as
`kemCt`.

**Format-byte allocation.** The reserved nibble layout
(`0x10`/`0x20`/`0x30` for ML-KEM-512/768/1024) is already used. A custom
KEM must pick a free KEM nibble in bits 4-5 (or coordinate with the catalog
if you intend the suite to be reachable from `OpenStream` preamble sniffing).

**Inner-suite delegation.** `sealChunk` / `openChunk` / `wipeKeys` /
`createPoolWorker` all bind through to the inner suite. Only `deriveKeys`
and the metadata fields are KEM-specific.

---

## Per-cipher contract tests

Per-cipher contract tests cover the behaviours that vary in shape
across the shipped suites: header binding, commitment field, and the
cipher's native key-committing properties. They live alongside the
cipher-agnostic stream contract tests in `test/unit/stream/`.

The cipher-agnostic block (round-trip, AAD, blob format, `OpenStream`
compat, error handling, wrong-key / tampered-tag / tampered-ct failure
modes) lives in `test/unit/stream/seal.test.ts` and runs for every
cipher via parameterisation over `test/unit/stream/_cipher-spec.ts`.

Each shipped cipher carries one `<cipher>-cipher-suite.test.ts`
implementing the same describe-block shape. Where the cipher's
behaviour differs (`SerpentCipher` does not header-bind, for example)
the describe block is still present, but the assertions are the
inverse and the test name describes the property being verified.

| Describe block | What it covers |
|---|---|
| `deriveKeys` | Commitment-or-no-commitment shape, plus header-binding effect on derived keys (or its absence for Serpent). |
| `Header binding` | Header-tamper effect on decrypt (failure for v3, no-effect for v2). |
| `Commitment` | Flipping a byte in the commitment region rejects on decrypt (v3 only; Serpent's block asserts the preamble has no commitment region). |
| Cipher-specific | Per-cipher behaviours below the shared blocks. |

The shipped contract-test files:

| File | Cipher |
|---|---|
| `test/unit/stream/serpent-cipher-suite.test.ts` | `SerpentCipher` |
| `test/unit/stream/xchacha20-cipher-suite.test.ts` | `XChaCha20Cipher` |
| `test/unit/stream/aes-cipher-suite.test.ts` | `AESGCMSIVCipher` |

Any new `CipherSuite` added to the catalog gets its own contract-test
file matching the same describe-block shape.

---

## Cross-References

| Document | Description |
| -------- | ----------- |
| [index](./README.md) | Project Documentation index |
| [architecture](./architecture.md) | Repository structure, build and CI, WASM modules, public API, test suite, and security posture |
| [lexicon](./lexicon.md) | Glossary of cryptographic terms |
| [authenticated encryption](./aead.md) | `Seal`, `SealStream`, `OpenStream`, `SealStreamPool` |
| [signing](./signing.md) | `Sign`, `SignStream`, `VerifyStream` (signature counterpart to the AEAD layer) |
| [signaturesuite](./signaturesuite.md) | `SignatureSuite` and the shipped suite catalog (signature counterpart to this interface) |
| [serpent](./serpent.md) | Serpent-256 TypeScript API and raw primitives |
| [chacha20](./chacha20.md) | ChaCha20 TypeScript API and raw primitives |
| [kyber](./kyber.md) | ML-KEM key encapsulation and `KyberSuite` |
| [types](./types.md) | TypeScript interfaces |

