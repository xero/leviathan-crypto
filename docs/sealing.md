# Authenticated Encryption

> Cipher-agnostic authenticated encryption for any scale. One-shot with `Seal`, chunked with `SealStream` and `OpenStream`, or parallel with `SealStreamPool`. All four share a wire format and accept any `CipherSuite`.

## Overview

`Seal`, `SealStream`, `OpenStream`, and `SealStreamPool` are the primary API for authenticated encryption in leviathan-crypto. They are cipher-agnostic: you pass a `CipherSuite` object at construction and the implementation handles key derivation, nonce management, and authentication for you.

The four classes form a natural progression. `Seal` handles data that fits in memory. `SealStream` and `OpenStream` handle data that arrives in chunks or is too large to buffer. `SealStreamPool` parallelizes the chunked approach across Web Workers. All four produce and consume the same wire format, so a `Seal` blob can be opened by `OpenStream` and vice versa.

Two cipher suites are included. A third wraps either with ML-KEM for post-quantum hybrid encryption.

| Suite | Cipher | Tag | Modules |
|---|---|---|---|
| `SerpentCipher` | Serpent-256 CBC + HMAC-SHA-256 | 32 B | `serpent`, `sha2` |
| `XChaCha20Cipher` | XChaCha20-Poly1305 | 16 B | `chacha20`, `sha2` |
| `KyberSuite` | ML-KEM + inner cipher | depends | `kyber`, `sha3`, + inner |

See [ciphersuite.md](./ciphersuite.md) for full cipher suite documentation.

---

## Security Model

The STREAM construction is based on [Hoang, Reyhanitabar, Rogaway, and Vizár (CRYPTO 2015)](https://eprint.iacr.org/2015/189.pdf). It provides online authenticated encryption with four guarantees.

**Per-chunk authentication.** Each chunk is individually authenticated. A tampered chunk is rejected immediately without decrypting anything that follows.

**Counter binding.** Each chunk's nonce includes a monotonic counter. Reordering or duplicating chunks produces a counter mismatch and authentication fails.

**Final-chunk detection.** The last chunk uses a distinct nonce flag (`TAG_FINAL` vs `TAG_DATA`). Truncating the stream by dropping the final chunk is detected because the opener expects a chunk marked final.

**Stream isolation.** Each stream generates a fresh 16-byte random nonce on construction. Two streams with the same key derive independent subkeys via HKDF and cannot interfere with each other.

> [!IMPORTANT]
> `SealStream` is single-use. After `finalize()` is called the derived keys are wiped and no further chunks can be sealed. Create a new `SealStream` for each message. `SealStreamPool.seal()` enforces this with a guard that throws on subsequent calls.

### WASM side-channel posture

All cryptographic computation runs in WASM outside the JavaScript JIT. Serpent's bitsliced S-box implementation and ChaCha20's quarter-round construction are both branchless and table-free, which eliminates data-dependent timing variation at the algorithm level. WASM lacks hardware-level constant-time guarantees, so this provides stronger posture than pure JavaScript but weaker than native constant-time code. If timing side channels are your primary threat model, a native cryptographic library with verified constant-time guarantees is more appropriate.

---

## Wire Format

### Header (20 bytes)

Every stream begins with a 20-byte header:

```
bytes:
    0: compound enum (bit 7 = framed flag, bit 6 = reserved, bits 0-5 = format ID)
 1-16: random nonce (16 bytes)
17-19: chunk size as u24 big-endian
```

**Format IDs:** `0x01` = XChaCha20-Poly1305, `0x02` = Serpent-256. KEM suites encode both the parameter set and inner cipher in a single byte. See [ciphersuite.md](./ciphersuite.md#kybersuite) for the full format enum table.

The 16-byte nonce is a HKDF salt, not a direct cipher nonce. `XChaCha20Cipher` passes it to HChaCha20 for subkey derivation. `SerpentCipher` uses it as the HKDF-SHA-256 salt to derive 96 bytes of enc/mac/iv key material.

The framed flag (bit 7) prefixes each chunk with a `u32be` length. Use framed mode for flat byte streams where chunks are concatenated without an external framing layer. Leave it off when the transport provides its own message boundaries such as WebSocket frames or IPC messages.

### Counter Nonce (12 bytes)

Each chunk is encrypted with a 12-byte nonce:

```
bytes:
 0-10: 11-byte big-endian counter (monotonically increasing)
   11: final flag (0x00 = TAG_DATA, 0x01 = TAG_FINAL)
```

The counter starts at 0 and increments with each chunk. The final chunk uses `TAG_FINAL` instead of `TAG_DATA`. A data chunk at counter N and a final chunk at counter N produce distinct nonces, so the construction never reuses a nonce.

### Key Derivation

HKDF-SHA-256 derives cipher-specific key material from the master key and the random nonce at stream construction:

| Cipher | HKDF info | Output | Structure |
|---|---|---|---|
| XChaCha20 | `xchacha20-sealstream-v2` | 32 B | HKDF → streamKey → HChaCha20 → subkey |
| Serpent | `serpent-sealstream-v2` | 96 B | `enc_key[0:32] \| mac_key[32:64] \| iv_key[64:96]` |

XChaCha20 performs an additional HChaCha20 subkey derivation step using the first 16 bytes of the nonce. The intermediate streamKey is wiped immediately after use.

Serpent derives three keys: an encryption key for CBC, a MAC key for HMAC-SHA-256, and an IV key for per-chunk IV derivation via `HMAC-SHA-256(iv_key, counterNonce)[0:16]`. The CBC IV is derived deterministically on both sides and never transmitted.

---

## API Reference

### Seal

`Seal` is a static class, never instantiated. It handles one-shot authenticated encryption and decryption. A `Seal` blob is structurally identical to a single-chunk `SealStream` output: `preamble || finalChunk(counter=0, TAG_FINAL)`. `OpenStream.finalize()` can open a `Seal` blob directly, and `Seal.decrypt()` can open a single-chunk `SealStream`.

```typescript
import { init, Seal, XChaCha20Cipher } from 'leviathan-crypto'
import { chacha20Wasm } from 'leviathan-crypto/chacha20/embedded'
import { sha2Wasm }     from 'leviathan-crypto/sha2/embedded'

await init({ chacha20: chacha20Wasm, sha2: sha2Wasm })

const key  = XChaCha20Cipher.keygen()
const blob = Seal.encrypt(XChaCha20Cipher, key, plaintext)
const pt   = Seal.decrypt(XChaCha20Cipher, key, blob)  // throws AuthenticationError on tamper
```

| Method | Returns | Description |
|---|---|---|
| `Seal.encrypt(suite, key, plaintext, opts?)` | `Uint8Array` | One-shot encrypt. Returns `preamble \|\| chunk`. |
| `Seal.decrypt(suite, key, blob, opts?)` | `Uint8Array` | One-shot decrypt. Throws `AuthenticationError` on tamper. |

**`opts.aad`** — optional `Uint8Array`. Additional Authenticated Data: authenticated but not encrypted. Pass the same value to both `encrypt` and `decrypt`.

---

### SealStream

> [!NOTE]
> All stream classes require `sha2` for HKDF key derivation. Load it alongside your cipher module before constructing any stream.

```typescript
import { init, SealStream } from 'leviathan-crypto'
import { XChaCha20Cipher } from 'leviathan-crypto/chacha20'
import { chacha20Wasm }    from 'leviathan-crypto/chacha20/embedded'
import { sha2Wasm }        from 'leviathan-crypto/sha2/embedded'

await init({ chacha20: chacha20Wasm, sha2: sha2Wasm })

const key      = XChaCha20Cipher.keygen()
const sealer   = new SealStream(XChaCha20Cipher, key, { chunkSize: 65536 })
const preamble = sealer.preamble  // send first

const ct0    = sealer.push(chunk0)
const ct1    = sealer.push(chunk1)
const ctLast = sealer.finalize(lastChunk)  // keys wiped
```

**Constructor:** `new SealStream(cipher, key, opts?)`

| Parameter | Type | Description |
|---|---|---|
| `cipher` | `CipherSuite` | `XChaCha20Cipher`, `SerpentCipher`, or a `KyberSuite` instance. |
| `key` | `Uint8Array` | Master key. Must be `cipher.keySize` bytes (32 for both symmetric suites). |
| `opts.chunkSize` | `number` | Max plaintext bytes per chunk. Range: [1024, 16777215]. Default: 65536. |
| `opts.framed` | `boolean` | Prepend `u32be` length prefix to each chunk. Default: false. |

| Method | Returns | Description |
|---|---|---|
| `push(chunk, { aad? })` | `Uint8Array` | Encrypt a data chunk. Must be ≤ chunkSize bytes. |
| `finalize(chunk, { aad? })` | `Uint8Array` | Encrypt the final chunk and wipe keys. Must be ≤ chunkSize bytes. |
| `toTransformStream()` | `TransformStream` | Web Streams API wrapper. Emits preamble first, then sealed chunks. Finalizes on stream close. |
| `preamble` | `Uint8Array` | The stream preamble (read-only). 20 bytes for symmetric suites. 20B header + KEM ciphertext for KEM suites. |

---

### OpenStream

```typescript
import { OpenStream }      from 'leviathan-crypto/stream'
import { XChaCha20Cipher } from 'leviathan-crypto/chacha20'
import { chacha20Wasm }    from 'leviathan-crypto/chacha20/embedded'
import { sha2Wasm }        from 'leviathan-crypto/sha2/embedded'

// init already called — preamble, key, and ciphertext chunks received from sender
const opener = new OpenStream(XChaCha20Cipher, key, preamble)

const pt0    = opener.pull(ct0)
const pt1    = opener.pull(ct1)
const ptLast = opener.finalize(ctLast)  // keys wiped
```

**Constructor:** `new OpenStream(cipher, key, preamble)`

Throws if the preamble format enum doesn't match the cipher, or if the preamble is too short.

| Parameter | Type | Description |
|---|---|---|
| `cipher` | `CipherSuite` | Must match the cipher that produced the preamble. |
| `key` | `Uint8Array` | Same master key used for sealing. |
| `preamble` | `Uint8Array` | The preamble from `SealStream.preamble`. Pass it directly. |

| Method | Returns | Description |
|---|---|---|
| `pull(chunk, { aad? })` | `Uint8Array` | Decrypt a data chunk. Throws `AuthenticationError` on tamper. |
| `finalize(chunk, { aad? })` | `Uint8Array` | Decrypt the final chunk and wipe keys. |
| `seek(index)` | `void` | Set the counter to `index`. Enables random access decryption. Must be a non-negative integer. |
| `toTransformStream()` | `TransformStream` | Web Streams API wrapper. Buffers one chunk to detect the final chunk. |

---

### SealStreamPool

Parallel batch encryption and decryption using Web Workers. Each worker holds its own WASM instance and a copy of the derived keys.

```typescript
import { init, SealStreamPool } from 'leviathan-crypto'
import { XChaCha20Cipher }      from 'leviathan-crypto/chacha20'
import { chacha20Wasm }         from 'leviathan-crypto/chacha20/embedded'
import { sha2Wasm }             from 'leviathan-crypto/sha2/embedded'

await init({ chacha20: chacha20Wasm, sha2: sha2Wasm })

const pool = await SealStreamPool.create(XChaCha20Cipher, key, {
  wasm: chacha20Wasm,
  workers: 4,
  chunkSize: 65536,
})

const ciphertext = await pool.seal(plaintext)
const decrypted  = await pool.open(ciphertext)
pool.destroy()
```

**`SealStreamPool.create(cipher, key, opts)`** — async factory.

| Option | Type | Default | Description |
|---|---|---|---|
| `wasm` | `WasmSource` or `Record<string, WasmSource>` | required | WASM source(s). Single value for XChaCha20. Record for Serpent: `{ serpent, sha2 }`. |
| `workers` | `number` | `navigator.hardwareConcurrency` (4 if unset) | Worker count. |
| `chunkSize` | `number` | `65536` | Chunk size in bytes. |
| `framed` | `boolean` | `false` | Framed mode. |
| `jobTimeout` | `number` | `30000` | Per-job timeout in ms. |

**Failure model.** Any error is fatal. Authentication failure, worker crash, or timeout all terminate every worker, wipe all keys, and mark the pool permanently dead. Pending promises reject. There is no retry and no worker replacement. Create a new pool for the next operation.

| Method / Property | Description |
|---|---|
| `seal(plaintext)` | Encrypt. Returns `Promise<Uint8Array>`. Single-use. Throws on subsequent calls. |
| `open(ciphertext)` | Decrypt. Returns `Promise<Uint8Array>`. Rejects empty ciphertext. |
| `destroy()` | Wipes keys and terminates workers. Safe to call multiple times. |
| `header` | The 20-byte stream header. Note: `SealStreamPool` exposes `.header` while `SealStream` exposes `.preamble` which also supports KEM preambles. |
| `dead` | `true` after any fatal error or `destroy()`. |
| `size` | Number of workers. |

---

### KyberSuite

`KyberSuite` wraps an ML-KEM instance and an inner `CipherSuite` into a hybrid post-quantum construction. The result plugs into `Seal`, `SealStream`, `OpenStream`, and `SealStreamPool` identically to a symmetric suite.

```typescript
import { init, SealStream, OpenStream } from 'leviathan-crypto'
import { KyberSuite, MlKem768 }         from 'leviathan-crypto/kyber'
import { XChaCha20Cipher }              from 'leviathan-crypto/chacha20'
import { kyberWasm }    from 'leviathan-crypto/kyber/embedded'
import { sha3Wasm }     from 'leviathan-crypto/sha3/embedded'
import { chacha20Wasm } from 'leviathan-crypto/chacha20/embedded'
import { sha2Wasm }     from 'leviathan-crypto/sha2/embedded'

await init({ kyber: kyberWasm, sha3: sha3Wasm, chacha20: chacha20Wasm, sha2: sha2Wasm })

const suite = KyberSuite(new MlKem768(), XChaCha20Cipher)
const { encapsulationKey: ek, decapsulationKey: dk } = suite.keygen()

// sender — encrypts with the public key
const sealer   = new SealStream(suite, ek)
const preamble = sealer.preamble  // 1108 bytes for MlKem768
const ct0      = sealer.push(chunk0)
const ctLast   = sealer.finalize(lastChunk)

// recipient — decrypts with the private key
const opener = new OpenStream(suite, dk, preamble)
const pt0    = opener.pull(ct0)
const ptLast = opener.finalize(ctLast)
```

See [kyber.md](./kyber.md) for key management, parameter set selection, and the full ML-KEM reference. See [ciphersuite.md](./ciphersuite.md#kybersuite) for format enum values and key derivation details.

---

### Per-chunk AAD

`push()` and `finalize()` on `SealStream` and `pull()` and `finalize()` on `OpenStream` all accept an optional `{ aad }` parameter for Additional Authenticated Data. AAD is authenticated but not encrypted. It binds each chunk to external context such as sequence numbers, metadata, or routing information without including that data in the ciphertext.

AAD applies per chunk, not per stream. Each chunk can carry different AAD. If you sealed a chunk with AAD you must provide the same value when opening it. A mismatch causes authentication to fail.

---

### AuthenticationError

`AuthenticationError` is thrown by `Seal.decrypt()`, `OpenStream.pull()`, `OpenStream.finalize()`, and `SealStreamPool.open()` when authentication fails. It extends `Error` and carries the cipher name in the message.

```typescript
import { AuthenticationError } from 'leviathan-crypto'

try {
  const pt = Seal.decrypt(XChaCha20Cipher, key, tampered)
} catch (e) {
  if (e instanceof AuthenticationError) {
    // ciphertext was modified
  }
}
```

Never attempt to recover plaintext after an `AuthenticationError`. The stream layer wipes output buffers before throwing.

---

> ## Cross-References
>
> - [index](./README.md) — Project Documentation index
> - [architecture](./architecture.md) — architecture overview, module relationships, buffer layouts, and build pipeline
> - [ciphersuite](./ciphersuite.md) — `SerpentCipher`, `XChaCha20Cipher`, `KyberSuite`, and the `CipherSuite` interface
> - [kyber](./kyber.md) — ML-KEM key encapsulation, parameter sets, and key management
> - [serpent](./serpent.md) — Serpent-256 raw primitives
> - [chacha20](./chacha20.md) — ChaCha20 raw primitives
> - [stream_audit](./stream_audit.md) — streaming AEAD composition audit
> - [exports](./exports.md) — complete export reference
> - [init](./init.md) — WASM loading and `WasmSource`
