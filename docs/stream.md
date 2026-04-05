# Streaming AEAD: SealStream / OpenStream

> [!NOTE] Cipher-agnostic streaming encryption and decryption using the STREAM construction. Supports XChaCha20-Poly1305 and Serpent-256 CBC+HMAC-SHA-256 via pluggable `CipherSuite` objects.

## Overview

`SealStream` and `OpenStream` implement chunked, authenticated encryption for data too large to buffer in memory or that arrives incrementally, such as file encryption, network streams, and database records. Each chunk is independently authenticated with a counter-bound nonce, which prevents reordering, truncation, and duplication attacks.

The stream layer is cipher-agnostic. Cipher-specific logic, such as key derivation, per-chunk encrypt/decrypt, and tag format, resides in `CipherSuite` objects passed during construction. This library includes two implementations:

| Object            | Cipher                         | Tag  | Padding | modules           |
| ----------------- | ------------------------------ | ---- | ------- | ----------------- |
| `XChaCha20Cipher` | XChaCha20-Poly1305             | 16 B | none    | `chacha20` + `sha2`* |
| `SerpentCipher`   | Serpent-256 CBC + HMAC-SHA-256 | 32 B | PKCS7   | `serpent`, `sha2` |

\* `sha2` is required by the stream layer for HKDF key derivation, not by
the cipher's pool workers.

This separation means five stream classes (`SealStream`, `OpenStream`, `SealStreamPool`, and the two cipher objects) replace what would otherwise be ten cipher-specific classes.

---

## Security Model

The STREAM construction is based on Hoang, Reyhanitabar, Rogaway, and Vizár (CRYPTO 2015), an Online Authenticated Encryption scheme with the following features:

- **Per-chunk authentication:** Each chunk is individually authenticated, and any tampered chunk is rejected immediately, without decrypting subsequent chunks.

- **Counter binding:** Each chunk's nonce includes a monotonic counter. Reordering or duplicating chunks produces a counter mismatch that causes authentication to fail.

- **Final-chunk flag:** The last chunk uses a distinct nonce flag (TAG_FINAL vs TAG_DATA). Truncating the stream by dropping the final chunk is detected because the opener expects a chunk with the final flag.

- **Stream isolation:** Each stream generates a fresh 16-byte random nonce upon construction. Because two streams with the same key derive independent subkeys via HKDF, they cannot interfere with each other.

> [!IMPORTANT]
> `SealStream` is single-use. After `finalize()` is called, the derived keys are wiped and no further chunks can be sealed. Create a new `SealStream` for each message. `SealStreamPool.seal()` enforces this with a guard that throws on subsequent invocations.

### WASM side-channel posture

WebAssembly (WASM) implementations offer the best side-channel resistance. WASM lacks hardware-level constant-time guarantees (e.g., i32x4.rotl is unavailable, and SIMD scheduling varies by engine), but Serpent's bitsliced implementation and ChaCha20's quarter-round algorithm are inherently branchless and table-free. This provides a stronger security posture than pure JavaScript, though it remains weaker than native constant-time code. For applications where timing side channels are a primary threat, a native cryptographic library with verified constant-time guarantees will be more appropriate than any WASM-based implementation.

---

## Wire Format

### Header (20 bytes)

Every stream begins with a 20-byte header:

```
bytes:
    0: compound enum (bit 7 = framed flag, bits 0-6 = format ID)
 1-16: random nonce (16 bytes)
17-19: chunk size as u24 big-endian
```

**Format IDs:** `0x01` = XChaCha20-Poly1305, `0x02` = Serpent-256.

The framed flag (bit 7) indicates whether each chunk is prefixed with a `u32be` length. Framed mode is for flat byte streams where chunks are concatenated without an external framing layer. Unframed mode assumes the transport provides its own message boundaries (WebSocket, IPC, etc).

### Counter Nonce (12 bytes)

Each chunk is encrypted with a 12-byte nonce:

```
bytes:
 0-10: 11-byte big-endian counter (monotonically increasing)
   11: final flag (0x00 = TAG_DATA, 0x01 = TAG_FINAL)
```

**The construction never reuses a nonce.** The counter starts at 0 and increments with each chunk. The final chunk uses `TAG_FINAL` (0x01) instead of `TAG_DATA` (0x00). This means a data chunk's nonce at counter N and a final chunk's nonce at counter N are distinct.

### Key Derivation

At stream construction, HKDF-SHA-256 derives cipher-specific key material from the master key and the random nonce:

| Cipher    | HKDF info                 | Output | Structure                                          |
| --------- | ------------------------- | ------ | -------------------------------------------------- |
| XChaCha20 | `xchacha20-sealstream-v2` | 32 B   | HKDF → streamKey → HChaCha20 → subkey              |
| Serpent   | `serpent-sealstream-v2`   | 96 B   | `enc_key[0:32] \| mac_key[32:64] \| iv_key[64:96]` |

XChaCha20 performs an additional HChaCha20 subkey derivation step after HKDF, using the first 16 bytes of the nonce. The intermediate streamKey is wiped immediately.

Serpent derives three keys: an encryption key for CBC, a MAC key for HMAC-SHA-256, and an IV key used to derive per-chunk IVs via `HMAC-SHA-256(iv_key, counterNonce)[0:16]`. The CBC IV is derived deterministically on both sides and is never transmitted.

---

## Cipher Suite Details

### XChaCha20Cipher

**Per chunk:** ChaCha20-Poly1305 AEAD (RFC 8439) with the derived subkey and 12-byte counter nonce. Chunk output is `ciphertext || tag(16)` with no padding.

**Overhead per chunk:** 16 bytes (Poly1305 tag).
### SerpentCipher

**Per chunk:** Serpent-256 CBC with PKCS7 padding, then HMAC-SHA-256. The HMAC covers `counterNonce || u32be(aad_len) || aad || ciphertext`.

The verify-then-decrypt ordering is **_critical_**. PKCS7 padding is evaluated only after HMAC authentication succeeds, preventing padding oracle attacks (Vaudenay 2002).

**Overhead per chunk:** 1-16 bytes PKCS7 padding + 32 bytes HMAC tag.

>[!NOTE]
>The asymmetry between the two ciphers is intentional. Serpent employs CBC+HMAC (encrypt-then-MAC) instead of a native AEAD mode because a standardized Serpent AEAD construction does not exist. This conservative approach, using well-understood primitives composed according to established patterns, aligns with Serpent's design philosophy, which prioritizes a strong security margin over performance.

---

## API Reference

### SealStream

> [!NOTE]
> All stream classes require `sha2` for HKDF key derivation. Call
> `init({ chacha20: chacha20Wasm, sha2: sha2Wasm })` (or the Serpent
> equivalent) before constructing any stream.

```typescript
import { SealStream } from 'leviathan-crypto/stream';
import { XChaCha20Cipher } from 'leviathan-crypto/chacha20';

const sealer = new SealStream(XChaCha20Cipher, key, { chunkSize: 65536 });

const header = sealer.header;           // Uint8Array(20) — send first
const ct0    = sealer.push(chunk0);     // encrypted chunk
const ct1    = sealer.push(chunk1);
const ctLast = sealer.finalize(tail);   // final chunk — keys wiped
```

**Constructor:** `new SealStream(cipher, key, opts?, _nonce?)`

|Parameter|Type|Description|
|---|---|---|
|`cipher`|`CipherSuite`|`XChaCha20Cipher` or `SerpentCipher`|
|`key`|`Uint8Array`|Master key. Must be `cipher.keySize` bytes (32 for both ciphers).|
|`opts.chunkSize`|`number`|Max plaintext bytes per chunk. Range: [1024, 16777215]. Default: 65536.|
|`opts.framed`|`boolean`|Prepend `u32be` length prefix to each chunk. Default: false.|

|Method|Returns|Description|
|---|---|---|
|`push(chunk, { aad? })`|`Uint8Array`|Encrypt a data chunk. Must be ≤ chunkSize bytes.|
|`finalize(chunk, { aad? })`|`Uint8Array`|Encrypt the final chunk and wipe keys. Must be ≤ chunkSize bytes.|
|`toTransformStream()`|`TransformStream`|Web Streams API wrapper. Emits header, then sealed chunks. Finalizes on stream close.|
|`header`|`Uint8Array`|The 20-byte stream header (read-only).|

---

### OpenStream

```typescript
import { OpenStream } from 'leviathan-crypto/stream';

const opener = new OpenStream(XChaCha20Cipher, key, header);

const pt0    = opener.pull(ct0);         // decrypted chunk
const pt1    = opener.pull(ct1);
const ptLast = opener.finalize(ctLast);  // final chunk — keys wiped
```

**Constructor:** `new OpenStream(cipher, key, header)`

| Parameter | Type          | Description                                     |
| --------- | ------------- | ----------------------------------------------- |
| `cipher`  | `CipherSuite` | Must match the cipher that produced the header. |
| `key`     | `Uint8Array`  | Same master key used for sealing.               |
| `header`  | `Uint8Array`  | The 20-byte header from the SealStream.         |

**Throws if the header's format enum doesn't match the cipher.**

| Method                      | Returns           | Description                                                                                   |
| --------------------------- | ----------------- | --------------------------------------------------------------------------------------------- |
| `pull(chunk, { aad? })`     | `Uint8Array`      | Decrypt a data chunk. Throws `AuthenticationError` on tamper.                                 |
| `finalize(chunk, { aad? })` | `Uint8Array`      | Decrypt the final chunk and wipe keys.                                                        |
| `seek(index)`               | `void`            | Set the counter to `index`. Enables random access decryption. Must be a non-negative integer. |
| `toTransformStream()`       | `TransformStream` | Web Streams API wrapper. Buffers one chunk to detect the final chunk.                         |

---

### SealStreamPool

Parallel batch encryption/decryption using Web Workers. Each worker holds its own WASM instance and a copy of the derived keys.

```typescript
import { init, SealStreamPool } from 'leviathan-crypto/stream';
import { XChaCha20Cipher } from 'leviathan-crypto/chacha20';
import { chacha20Wasm } from 'leviathan-crypto/chacha20/embedded';
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded';

await init({ chacha20: chacha20Wasm, sha2: sha2Wasm });

const pool = await SealStreamPool.create(XChaCha20Cipher, key, {
  wasm: chacha20Wasm,
  workers: 4,
  chunkSize: 65536,
});

const ciphertext = await pool.seal(plaintext);   // single-use
const decrypted  = await pool.open(ciphertext);
pool.destroy();                                   // wipe keys, kill workers
```

**`SealStreamPool.create(cipher, key, opts)`** — async factory.

| Option       | Type                                         | Default                                        | Description                                                                           |
| ------------ | -------------------------------------------- | ---------------------------------------------- | ------------------------------------------------------------------------------------- |
| `wasm`       | `WasmSource` or `Record<string, WasmSource>` | (**required**)                                 | WASM source(s). Single value for XChaCha20, Record for Serpent (`{ serpent, sha2 }`). |
| `workers`    | `number`                                     | `navigator.hardwareConcurrency` (`4` if unset) | Worker count.                                                                         |
| `chunkSize`  | `number`                                     | `65536`                                        | Chunk size in bytes.                                                                  |
| `framed`     | `boolean`                                    | `false`                                        | Framed mode.                                                                          |
| `jobTimeout` | `number`                                     | `30000`                                        | Per-job timeout in ms.                                                                |

**Failure model:** Any error — authentication failure, worker crash, or timeout — is fatal. All workers are terminated, all keys are wiped, and the pool is permanently dead. Pending promises are rejected. There is no retry and no worker replacement. Create a new pool for the next operation.

| Method / Property  | Description                                                                     |
| ------------------ | ------------------------------------------------------------------------------- |
| `seal(plaintext)`  | Encrypt. Returns `Promise<Uint8Array>`. Single-use. throws on subsequent calls. |
| `open(ciphertext)` | Decrypt. Returns `Promise<Uint8Array>`. Rejects empty ciphertext.               |
| `destroy()`        | Idempotently wipes keys and terminate workers.                                  |
| `header`           | The 20-byte stream header.                                                      |
| `dead`             | `true` after any fatal error or `destroy()`.                                    |
| `size`             | Number of workers.                                                              |

---

## CipherSuite Interface

The `CipherSuite` interface serves as the extension point for adding new ciphers. The included implementations, `XChaCha20Cipher` and `SerpentCipher`, are plain `const` objects rather than classes.

| Field         | Type                | Description                                                         |
| ------------- | ------------------- | ------------------------------------------------------------------- |
| `formatEnum`  | `number`            | Wire format ID (bits 0-6 of header byte 0).                         |
| `hkdfInfo`    | `string`            | HKDF info string for domain separation.                             |
| `keySize`     | `number`            | Required master key length in bytes.                                |
| `tagSize`     | `number`            | Authentication tag size in bytes.                                   |
| `padded`      | `boolean`           | Whether ciphertext includes padding (affects pool chunk splitting). |
| `wasmModules` | `readonly string[]` | WASM modules required by this cipher.                               |

| Method                                       | Description                                        |
| -------------------------------------------- | -------------------------------------------------- |
| `deriveKeys(masterKey, nonce)`               | HKDF key derivation. Returns opaque `DerivedKeys`. |
| `sealChunk(keys, counterNonce, chunk, aad?)` | Encrypt one chunk.                                 |
| `openChunk(keys, counterNonce, chunk, aad?)` | Decrypt one chunk or throw `AuthenticationError`.  |
| `wipeKeys(keys)`                             | Zero derived key material.                         |
| `createPoolWorker(modules)`                  | Create a Web Worker for pool use.                  |

---

## Per-Chunk AAD

Both `push()`/`finalize()` on the sealer and `pull()`/`finalize()` on the opener accept an optional `{ aad }` parameter for Additional Authenticated Data (AAD). AAD is authenticated but not encrypted, binding each chunk to external context such as sequence numbers, metadata, or routing info, without including that data in the ciphertext.

AAD is applied on a per-chunk, not per-stream, basis, meaning each chunk can have different AAD. If a chunk was sealed with AAD, the same AAD must be provided when opening it; otherwise, authentication will fail.

---

> ## Cross-References
>
> - [exports](./exports.md) — complete export reference
> - [types](./types.md) — `CipherSuite`, `DerivedKeys`, `SealStreamOpts`, `PoolOpts`
> - [serpent](./serpent.md) — `SerpentCipher` properties and Serpent-256 primitives
> - [chacha20](./chacha20.md) — `XChaCha20Cipher` properties and ChaCha20 primitives
> - [init](./init.md) — WASM loading and `WasmSource`
> - [architecture](./architecture.md) — module structure and three-tier design
