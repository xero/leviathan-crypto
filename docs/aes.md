<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### AES TypeScript API

See [AES WASM module reference](./asm_aes.md) for implementation internals and buffer layout.

> ### Table of Contents
> - [Overview](#overview)
> - [Security Notes](#security-notes)
> - [Module Init](#module-init)
> - [API Reference](#api-reference)
>   - [AESGCMSIVCipher](#aesgcmsivcipher)
>   - [AES](#aes)
>   - [AESCtr](#aesctr)
>   - [AESCbc](#aescbc)
>   - [AESGCM](#aesgcm)
>   - [AESGCMSIV](#aesgcmsiv)
> - [AESGenerator](#aesgenerator)
> - [Usage Examples](#usage-examples)
> - [Error Conditions](#error-conditions)

---

## Overview

`AESGCMSIVCipher` is the recommended AES API for new code. Pass it to `Seal`
for one-shot AEAD or to `SealStream`/`OpenStream`/`SealStreamPool` for
streaming. It composes AES-256-GCM-SIV (RFC 8452, nonce-misuse-resistant)
with HKDF-SHA-256 key derivation and a 32-byte key commitment that closes
the Invisible Salamanders attack surface. Reusing a nonce does not produce
a catastrophic break the way it does with AES-GCM.

For lower-level use, six classes are exposed:

- **`AES`** raw 16-byte block encrypt and decrypt
- **`AESCtr`** counter-mode streaming (unauthenticated)
- **`AESCbc`** CBC with PKCS7 padding (unauthenticated, requires opt-in)
- **`AESGCM`** GCM authenticated AEAD (NIST SP 800-38D §7)
- **`AESGCMSIV`** GCM-SIV authenticated AEAD (RFC 8452, nonce-misuse-resistant)
- **`AESGenerator`** AES-256 ECB counter-mode PRF for `Fortuna`

AES-128, AES-192, and AES-256 are supported across the family, **except**
`AESGCMSIV` which is AES-128/256 only. RFC 8452 §6 does not define an
AES-192-GCM-SIV variant.

The implementation is bitsliced over WebAssembly v128 SIMD, processes 8
blocks in parallel, and uses a constant-time tower-field S-box (Canright
2005). FIPS 197 (final update 2023) §5.1, §5.2, §5.3.5, Appendix B.

---

## Security Notes

> [!IMPORTANT]
> Read this section carefully before using any AES class. These are not
> theoretical concerns. Ignoring them will render encryption useless.

### `AESCbc`, `AESCtr`, and `AESGCM` are not nonce-misuse-resistant

`AESGCM` is authenticated, but reusing a (key, IV) pair under GCM is
catastrophic: an attacker recovers the GHASH authentication subkey `H` and
can forge tags for arbitrary messages. `AESCbc` and `AESCtr` are
unauthenticated outright, so any tampered ciphertext decrypts to garbage
without indication.

[`Seal`](./aead.md#seal) with [`AESGCMSIVCipher`](./ciphersuite.md#aesgcmsivcipher)
is the safe default. AES-GCM-SIV's authentication tag is a deterministic
function of the plaintext, so nonce reuse leaks only equality of plaintexts
under the same nonce, not the entire keystream and not the MAC subkey.

### Always generate a fresh random nonce per message

For `AESGCM` and `AESGCMSIV`, use `randomBytes(12)`. For `AESCtr` use
`randomBytes(16)`. For `AESCbc` use `randomBytes(16)` and treat it as the
IV. The 96-bit nonce of `AESGCM` only stays collision-safe for roughly
2^32 messages under the same key when chosen randomly; rotate keys before
that bound.

### `AESGCMSIV` is single-shot and capped at 64 KiB

The standalone `AESGCMSIV` primitive is a one-shot AEAD bounded by the
AES module's chunk buffer. Plaintext and AAD each cap at 65536 bytes per
call. Larger messages must use `SealStream` with `AESGCMSIVCipher`, which
chunks internally.

### `AESGCMSIVCipher` is AES-256 only

The standalone `AESGCMSIV` class supports AES-128 and AES-256. The
`CipherSuite` handle hardcodes AES-256 to keep the wire format uniform
across deployments. The on-disk `formatEnum: 0x04` always means
AES-256-GCM-SIV.

The same restriction applies to the internal `sivAeadEncrypt` /
`sivAeadDecrypt` helpers in `src/ts/aes/ops.ts` and to the AES pool
worker, both fix the key length at 32 bytes. A 16-byte key reaches
those paths only by misuse and throws
`RangeError('AES-GCM-SIV: key must be 32 bytes (got 16)')`. Reach for
the `AESGCMSIV` class directly (not the cipher suite) when AES-128 is
required.

### Module exclusivity

`AESCbc`, `AESCtr`, and `AESGCM` are stateful and hold exclusive access to
the `aes` WASM module from construction until `dispose()`. While one is
live, constructing another AES-using stateful class throws, and atomic
calls on `AES`, `AESGCMSIV`, `AESGenerator`, or `AESGCMSIVCipher` throw too.
`AES`, `AESGCMSIV`, `AESGenerator`, and `AESGCMSIVCipher` are atomic and
acquire the module per call. Pool workers are unaffected since each
worker owns its own WASM instance.

### Call `dispose()` when done

Every AES class holds key material in WebAssembly memory. Wrap every
stateful instance in `try { ... } finally { x.dispose() }`. `dispose()`
zeroes the key schedule, the working state, and the per-mode scratch
buffers, then releases the exclusivity token.

---

## Module Init

Each module subpath exports its own init function for tree-shakeable imports.

### `aesInit(source)`

Initializes only the aes WASM binary. Equivalent to calling the root
`init({ aes: aesWasm })` without pulling the other modules into the bundle.

**Signature:**

```typescript
async function aesInit(source: WasmSource): Promise<void>
```

**Usage:**

```typescript
import { aesInit, AES } from 'leviathan-crypto/aes'
import { aesWasm } from 'leviathan-crypto/aes/embedded'

await aesInit(aesWasm)
```

`AESGCMSIVCipher` (and therefore `Seal`, `SealStream`, `OpenStream` when
constructed with it) additionally requires `sha2` for HKDF-SHA-256 key
derivation. `AESGenerator` only needs `aes`.

---

## API Reference

All classes require their WASM modules to be initialized before
construction. `AES`, `AESCbc`, `AESCtr`, `AESGCM`, `AESGCMSIV`, and
`AESGenerator` need `aes`. `AESGCMSIVCipher` needs `aes` plus `sha2`.

### AESGCMSIVCipher

`CipherSuite` implementation for AES-256-GCM-SIV streaming. Pass to
`Seal`, `SealStream`, `OpenStream`, or `SealStreamPool`. Never instantiated
directly.

Requires `init({ aes: aesWasm, sha2: sha2Wasm })`.

| Property | Value |
|----------|-------|
| `formatEnum` | `0x04` |
| `formatName` | `'aes-gcm-siv'` |
| `hkdfInfo` | `'aes-gcm-siv-sealstream-v3'` |
| `keySize` | `32` |
| `tagSize` | `16` |
| `commitmentSize` | `32` |
| `padded` | `false` |
| `wasmChunkSize` | `65536` |
| `wasmModules` | `['aes']` |

#### `AESGCMSIVCipher.keygen(): Uint8Array`

Returns `randomBytes(32)`. Convenience method, not on the
[`CipherSuite`](./ciphersuite.md) interface.

#### Usage with `Seal`

```typescript
import { init, Seal, AESGCMSIVCipher } from 'leviathan-crypto'
import { aesWasm }  from 'leviathan-crypto/aes/embedded'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await init({ aes: aesWasm, sha2: sha2Wasm })

const key  = AESGCMSIVCipher.keygen()
const blob = Seal.encrypt(AESGCMSIVCipher, key, plaintext)
const pt   = Seal.decrypt(AESGCMSIVCipher, key, blob)   // throws on tamper
```

#### Usage with `SealStream` / `OpenStream`

```typescript
import { SealStream, OpenStream } from 'leviathan-crypto/stream'
import { AESGCMSIVCipher } from 'leviathan-crypto/aes'

const sealer   = new SealStream(AESGCMSIVCipher, key)
const preamble = sealer.preamble       // 20 bytes, send before first chunk
const ct0      = sealer.push(chunk0)
const ctLast   = sealer.finalize(lastChunk)

const opener = new OpenStream(AESGCMSIVCipher, key, preamble)
const pt0    = opener.pull(ct0)
const ptLast = opener.finalize(ctLast)
```

See [aead.md](./aead.md) for the full `Seal`, `SealStream`, and
`OpenStream` API, and [ciphersuite.md](./ciphersuite.md) for the
`CipherSuite` interface and the wire-format contract.

---

### AES

Raw AES block encrypt and decrypt. Operates on exactly 16-byte blocks.
Atomic, no exclusivity guard.

```typescript
class AES {
	constructor()
	loadKey(key: Uint8Array): void
	encryptBlock(plaintext: Uint8Array): Uint8Array
	decryptBlock(ciphertext: Uint8Array): Uint8Array
	dispose(): void
}
```

#### `constructor()`

Creates a new AES instance. Throws if `init({ aes: aesWasm })` has not
been called.

---

#### `loadKey(key: Uint8Array): void`

Expands `key` into the WASM key schedule. The schedule covers both forward
encryption rounds and the FIPS 197 §5.3.5 Equivalent Inverse Cipher rounds
(InvMixColumns is pre-applied to inverse round keys 1..Nr-1 inside the
schedule, so decrypt's round loop mirrors encrypt). Must be called before
`encryptBlock` or `decryptBlock`.

- **key**: 16, 24, or 32 bytes (AES-128 / 192 / 256). Throws `RangeError`
  if the length is invalid.

---

#### `encryptBlock(plaintext: Uint8Array): Uint8Array`

Encrypts a single 16-byte block and returns the 16-byte ciphertext.
FIPS 197 §5.1 Algorithm 1, Nr ∈ {10, 12, 14}.

- **plaintext**: exactly 16 bytes. Throws `RangeError` if the length is
  not 16.

---

#### `decryptBlock(ciphertext: Uint8Array): Uint8Array`

Decrypts a single 16-byte block and returns the 16-byte plaintext.
FIPS 197 §5.3.5 Equivalent Inverse Cipher.

- **ciphertext**: exactly 16 bytes. Throws `RangeError` if the length is
  not 16.

---

#### `dispose(): void`

Wipes WASM key material and intermediate buffers. Always call after use.

---

### AESCtr

AES in Counter (CTR) mode. Encrypts and decrypts data of any length as a
stream of chunks.

> [!WARNING]
> CTR mode is unauthenticated. An attacker can flip ciphertext bits without
> detection. Use [`Seal`](./aead.md#seal) with
> [`AESGCMSIVCipher`](./ciphersuite.md#aesgcmsivcipher) for authenticated
> encryption, or pair `AESCtr` with HMAC-SHA-256 in Encrypt-then-MAC order.

> [!CAUTION]
> `AESCtr` is stateful and holds exclusive access to the `aes` WASM module
> for its entire lifetime. Constructing a second `AESCbc`/`AESCtr`/`AESGCM`
> or invoking any atomic AES class while this instance is live throws.
> Call `dispose()` when done. Pool workers are unaffected.

```typescript
class AESCtr {
	constructor(opts: { dangerUnauthenticated: true })
	loadKey(key: Uint8Array): void
	setNonce(nonce: Uint8Array): void
	encrypt(plaintext: Uint8Array): Uint8Array
	decrypt(ciphertext: Uint8Array): Uint8Array
	dispose(): void
}
```

The counter is 128-bit big-endian, matching SP 800-38A Appendix B.1 and
the §F.5 worked examples. The 16-byte nonce is the full initial counter
block, not a separate nonce/counter split. The counter advances across
`encrypt`/`decrypt` calls and is reset only by a subsequent `setNonce()`.

#### `constructor(opts: { dangerUnauthenticated: true })`

Creates a new AESCtr instance and acquires exclusive access to the `aes`
module. Throws if the module is not initialized or another stateful AES
instance currently owns it. Throws if `{ dangerUnauthenticated: true }`
is not passed:

```
leviathan-crypto: AESCtr is unauthenticated, use Seal with AESGCMSIVCipher, SerpentCipher, or XChaCha20Cipher instead. To use AESCtr directly, pass { dangerUnauthenticated: true }.
```

The opt-in matches `AESCbc` and `SerpentCtr`, putting CTR/CBC on equal
footing as the only unauthenticated AES modes you can construct.

---

#### `loadKey(key: Uint8Array): void`

Expands `key` into the WASM key schedule. Must be called before
`setNonce`/`encrypt`/`decrypt`.

- **key**: 16, 24, or 32 bytes. Throws `RangeError` if the length is
  invalid.

---

#### `setNonce(nonce: Uint8Array): void`

Sets the 128-bit initial counter block and resets the working counter so
subsequent calls start at this value.

- **nonce**: exactly 16 bytes, must be unique per (key, message) pair.
  Throws `RangeError` if the length is not 16.

---

#### `encrypt(plaintext: Uint8Array): Uint8Array`

XORs `plaintext` with the AES CTR keystream. The counter advances by
`ceil(plaintext.length / 16)` blocks; counter state persists across calls
until `setNonce()` resets it.

- **plaintext**: any length. Internally chunked to the WASM module's
  64 KiB chunk buffer.

> [!NOTE]
> Always uses the 8-wide SIMD path (`encryptChunk_simd`). SIMD is
> required by the AES module; `init()` throws on runtimes without it.

---

#### `decrypt(ciphertext: Uint8Array): Uint8Array`

Alias for `encrypt`. CTR mode is symmetric.

---

#### `dispose(): void`

Wipes WASM state and releases exclusive module access. Idempotent. After
disposal, every method throws `AESCtr: instance has been disposed`.

---

### AESCbc

AES in Cipher Block Chaining (CBC) mode with automatic PKCS7 padding.
Encrypts and decrypts entire messages in a single call.

> [!WARNING]
> CBC mode is unauthenticated. Always authenticate the output with
> HMAC-SHA-256 (Encrypt-then-MAC) or use
> [`Seal`](./aead.md#seal) with
> [`AESGCMSIVCipher`](./ciphersuite.md#aesgcmsivcipher) instead.

> [!CAUTION]
> `AESCbc` is stateful and holds exclusive access to the `aes` WASM module
> for its entire lifetime. Constructing a second `AESCbc`/`AESCtr`/`AESGCM`
> or invoking any atomic AES class while this instance is live throws.
> Call `dispose()` when done.

```typescript
class AESCbc {
	constructor(opts: { dangerUnauthenticated: true })
	encrypt(key: Uint8Array, iv: Uint8Array, plaintext: Uint8Array): Uint8Array
	decrypt(key: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array): Uint8Array
	dispose(): void
}
```

#### `constructor(opts: { dangerUnauthenticated: true })`

Creates a new AESCbc instance. Throws if `init({ aes: aesWasm })` has
not been called. Throws if `{ dangerUnauthenticated: true }` is not
passed:

```
leviathan-crypto: AESCbc is unauthenticated, use Seal with SerpentCipher or XChaCha20Cipher instead. To use AESCbc directly, pass { dangerUnauthenticated: true }.
```

---

#### `encrypt(key, iv, plaintext): Uint8Array`

Encrypts plaintext with AES CBC + PKCS7 padding. The returned ciphertext
is always a multiple of 16 bytes and is at least 16 bytes longer than the
input.

- **key**: 16, 24, or 32 bytes. Throws `RangeError` if the length is
  invalid.
- **iv**: exactly 16 bytes, random and unique per (key, message). Throws
  `RangeError` if the length is not 16.
- **plaintext**: any length including zero. PKCS7 padding is applied
  automatically.

---

#### `decrypt(key, iv, ciphertext): Uint8Array`

Decrypts AES CBC ciphertext and strips PKCS7 padding.

- **key**: 16, 24, or 32 bytes. Throws `RangeError` if the length is
  invalid.
- **iv**: exactly 16 bytes, must match the IV used for encryption.
- **ciphertext**: a non-zero multiple of 16 bytes. Throws
  `RangeError('invalid ciphertext')` on any failure: zero length,
  non-multiple-of-16 length, or invalid PKCS7 padding. The single message
  and branch-free padding check close the Vaudenay 2002 padding-oracle
  surface; a caller cannot distinguish failure modes by message or by
  timing.

> [!NOTE]
> Decryption uses the 8-wide SIMD path (`cbcDecryptChunk_simd`). CBC
> encryption has no SIMD variant because each ciphertext block depends
> on the previous one.

---

#### `dispose(): void`

Wipes WASM state and releases exclusive module access. Idempotent. After
disposal, `encrypt` and `decrypt` throw `AESCbc: instance has been disposed`.

---

#### Security, direct use of `AESCbc`

`AESCbc` is unauthenticated. If you use it directly via
`{ dangerUnauthenticated: true }`, you are responsible for:

1. Authenticating the ciphertext (HMAC-SHA-256 in Encrypt-then-MAC order)
2. Verifying the HMAC **before** calling `decrypt()`
3. Using a unique, random IV per (key, message) pair

The single generic `'invalid ciphertext'` error and constant-time padding
validation mitigate padding-oracle attacks (Vaudenay 2002) on callers that
surface errors to remote parties. The authenticated composition
`AESGCMSIVCipher` is the recommended path.

---

### AESGCM

AES in Galois/Counter Mode (NIST SP 800-38D §7). Authenticated AEAD with a
128-bit tag. Tag length is fixed; truncated tags (32/64/96/104/112/120) are
out of scope.

> [!CAUTION]
> `AESGCM` is stateful and holds exclusive access to the `aes` WASM module
> for its entire lifetime. Constructing a second `AESCbc`/`AESCtr`/`AESGCM`
> or invoking any atomic AES class while this instance is live throws.
> Call `dispose()` when done.

> [!WARNING]
> Reusing a (key, IV) pair under AES-GCM is catastrophic: an attacker
> recovers the GHASH subkey and can forge tags for arbitrary messages. Use
> [`AESGCMSIV`](#aesgcmsiv) or
> [`AESGCMSIVCipher`](./ciphersuite.md#aesgcmsivcipher) when nonce
> uniqueness is hard to guarantee.

```typescript
class AESGCM {
	constructor()
	seal(key: Uint8Array, iv: Uint8Array, aad: Uint8Array, pt: Uint8Array): Uint8Array
	open(key: Uint8Array, iv: Uint8Array, aad: Uint8Array, sealed: Uint8Array): Uint8Array
	dispose(): void
}
```

`seal()` returns `ciphertext || tag` (length `pt.length + 16`).
`open()` expects the same concatenated format.

#### `constructor()`

Creates a new AESGCM instance and acquires exclusive access to the `aes`
module. Throws if the module is not initialized or another stateful AES
instance owns it.

---

#### `seal(key, iv, aad, pt): Uint8Array`

Authenticated encryption.

- **key**: 16, 24, or 32 bytes (AES-128 / 192 / 256).
- **iv**: 1 to 65536 bytes. The 12-byte (96-bit) IV is the recommended
  fast path: J0 is set to `iv || 0x00000001` directly. Other lengths
  trigger a GHASH-based J0 derivation that costs an extra pass over the IV.
- **aad**: 0 to 65536 bytes. May be empty.
- **pt**: 0 to `2^36 - 32` bytes (SP 800-38D §5.2.1.1). May be empty.

Returns ciphertext concatenated with the 128-bit tag.

---

#### `open(key, iv, aad, sealed): Uint8Array`

Authenticated decryption. Performs verify-before-decrypt: the entire
ciphertext is absorbed into GHASH and the tag is computed and
constant-time-compared with the received tag before the ciphertext is
decrypted to plaintext. This avoids leaking decrypted bytes to higher
layers when verification fails.

Throws `RangeError('authentication failed')` on tag mismatch, on
too-short input, or on any spec-violating length. The same generic error
covers every failure mode, so no detail is leaked about which check failed.
WASM buffers are wiped before the throw.

---

#### `dispose(): void`

Wipes WASM state and releases exclusive module access. Idempotent.

---

### AESGCMSIV

AES-128-GCM-SIV / AES-256-GCM-SIV (RFC 8452). Nonce-misuse-resistant
authenticated AEAD with a 128-bit tag. Atomic single-shot AEAD: each
`seal`/`open` call processes one complete message bounded by 64 KiB of
plaintext.

```typescript
class AESGCMSIV {
	constructor(key: Uint8Array)
	seal(nonce: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array): Uint8Array
	open(nonce: Uint8Array, sealed: Uint8Array, aad?: Uint8Array): Uint8Array
	dispose(): void
}
```

`seal()` returns `ciphertext || tag` (length `plaintext.length + 16`).
`open()` expects the same concatenated format. AES-192 keys are rejected;
RFC 8452 §6 does not define an AES-192-GCM-SIV variant.

#### `constructor(key: Uint8Array)`

Creates a new AESGCMSIV instance bound to `key`. The key is defensively
copied; mutations to the caller's buffer do not affect the instance.

- **key**: 16 bytes (AES-128-GCM-SIV) or 32 bytes (AES-256-GCM-SIV).
  Throws `RangeError` on any other length, including 24 bytes.

This class does **not** hold exclusive module access. Each `seal`/`open`
call acquires the module, runs, and releases.

---

#### `seal(nonce, plaintext, aad?): Uint8Array`

Authenticated encryption.

- **nonce**: exactly 12 bytes. RFC 8452 §6 fixes nonce length at 96 bits.
- **plaintext**: 0 to 65536 bytes. May be empty.
- **aad**: optional, 0 to 65536 bytes. Defaults to empty.

Returns ciphertext concatenated with the 128-bit tag.

---

#### `open(nonce, sealed, aad?): Uint8Array`

Authenticated decryption. Tag verification routes through
`constantTimeEqual` from the dedicated `ct` WASM module. On tag mismatch,
the WASM `sivWipeOnFail` helper zeroes the decrypted-but-unauthenticated
plaintext at `CHUNK_PT_OFFSET` before this method throws, the bytes
never become reachable from JS.

Throws `AuthenticationError('siv')` on tag mismatch, on too-short
`sealed`, or on any spec-violating length. The same error covers every
failure mode.

---

#### `dispose(): void`

Wipes the in-memory copy of the key. Idempotent. Subsequent calls to
`seal` or `open` throw. WASM-side state is wiped at the end of every
successful operation regardless of `dispose()`.

---

## AESGenerator

AES-256 ECB counter-mode PRF for Fortuna's generator slot. Implements the
`Generator` interface (Practical Cryptography, Ferguson & Schneier 2003
§9.4). This is the spec-canonical Fortuna primitive; `SerpentGenerator`
and `ChaCha20Generator` are deliberate spec deviations available for
deployments that prefer alternative primitive families.

`AESGenerator` is a plain `const` object, not a class. No instantiation,
no `dispose()`. Requires `init({ aes: aesWasm })`. See
[fortuna.md](./fortuna.md) for full usage with `Fortuna.create()`.

| Property | Value |
|----------|-------|
| `keySize` | `32` |
| `blockSize` | `16` |
| `counterSize` | `16` |
| `wasmModules` | `['aes']` |

### `AESGenerator.generate(key, counter, n): Uint8Array`

Produces `n` bytes of pseudorandom output by encrypting successive
16-byte counter values in ECB mode. Neither input is mutated. WASM key
material, key schedule, and last-block scratch are wiped before return,
along with the JS-heap counter copy.

| Parameter | Type | Description |
|-----------|------|-------------|
| `key` | `Uint8Array` | 32 bytes (256-bit AES key) |
| `counter` | `Uint8Array` | 16 bytes, treated as a little-endian integer |
| `n` | `number` | Output byte count: 0 ≤ n ≤ 2³⁰ |

**Returns** a new `Uint8Array` of length `n`.

**Throws:**
- `RangeError('AESGenerator: key must be 32 bytes (got N)')` if key length ≠ 32
- `RangeError('AESGenerator: counter must be 16 bytes (got N)')` if counter length ≠ 16
- `RangeError('AESGenerator: n must be a non-negative safe integer <= 2^30 (got N)')` if n is out of range
- `Error` if another stateful instance currently owns the `aes` WASM module

### Usage with `Fortuna`

```typescript
import { init, Fortuna } from 'leviathan-crypto'
import { AESGenerator } from 'leviathan-crypto/aes'
import { SHA256Hash } from 'leviathan-crypto/sha2'
import { aesWasm }  from 'leviathan-crypto/aes/embedded'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await init({ aes: aesWasm, sha2: sha2Wasm })
const rng = await Fortuna.create({ generator: AESGenerator, hash: SHA256Hash })
const bytes = rng.get(32)
rng.stop()
```

---

## Usage Examples

### Example 1: Seal with AESGCMSIVCipher (recommended)

```typescript
import { init, Seal, AESGCMSIVCipher } from 'leviathan-crypto'
import { aesWasm }  from 'leviathan-crypto/aes/embedded'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await init({ aes: aesWasm, sha2: sha2Wasm })

const key       = AESGCMSIVCipher.keygen()
const plaintext = new TextEncoder().encode('Authenticated secret message.')
const blob      = Seal.encrypt(AESGCMSIVCipher, key, plaintext)
const decrypted = Seal.decrypt(AESGCMSIVCipher, key, blob)

console.log(new TextDecoder().decode(decrypted))
// "Authenticated secret message."
```

### Example 2: AESGCM direct (advanced)

```typescript
import { init, AESGCM, randomBytes } from 'leviathan-crypto'
import { aesWasm } from 'leviathan-crypto/aes/embedded'

await init({ aes: aesWasm })

const key = randomBytes(32)              // AES-256
const iv  = randomBytes(12)              // 96-bit fast path
const aad = new TextEncoder().encode('header-v1')
const pt  = new TextEncoder().encode('Hello, AES-GCM.')

const gcm = new AESGCM()
try {
	const sealed    = gcm.seal(key, iv, aad, pt)        // ct || tag
	const decrypted = gcm.open(key, iv, aad, sealed)    // throws on tamper
	console.log(new TextDecoder().decode(decrypted))
} finally {
	gcm.dispose()
}
```

### Example 3: AESGCMSIV direct (single-shot, misuse-resistant)

```typescript
import { init, AESGCMSIV, randomBytes } from 'leviathan-crypto'
import { aesWasm } from 'leviathan-crypto/aes/embedded'

await init({ aes: aesWasm })

const key   = randomBytes(32)            // 16 (AES-128) or 32 (AES-256)
const nonce = randomBytes(12)            // exactly 12 bytes
const aad   = new TextEncoder().encode('header-v1')
const pt    = new TextEncoder().encode('Misuse-resistant AEAD.')

const aead = new AESGCMSIV(key)
try {
	const sealed    = aead.seal(nonce, pt, aad)
	const decrypted = aead.open(nonce, sealed, aad)     // throws AuthenticationError on tamper
	console.log(new TextDecoder().decode(decrypted))
} finally {
	aead.dispose()
}
```

### Example 4: AESCtr (advanced, unauthenticated)

```typescript
import { init, AESCtr, randomBytes } from 'leviathan-crypto'
import { aesWasm } from 'leviathan-crypto/aes/embedded'

await init({ aes: aesWasm })

const key   = randomBytes(32)
const nonce = randomBytes(16)            // full 128-bit IC, never reuse with same key

const ctr = new AESCtr({ dangerUnauthenticated: true })
try {
	ctr.loadKey(key)
	ctr.setNonce(nonce)
	const c1 = ctr.encrypt(new TextEncoder().encode('Hello, '))
	const c2 = ctr.encrypt(new TextEncoder().encode('world!'))

	ctr.setNonce(nonce)                  // reset counter to decrypt
	const p1 = ctr.decrypt(c1)
	const p2 = ctr.decrypt(c2)
	console.log(new TextDecoder().decode(p1) + new TextDecoder().decode(p2))
} finally {
	ctr.dispose()
}
```

> [!IMPORTANT]
> CTR mode is unauthenticated. An attacker can tamper with ciphertext
> without detection. Use `Seal` with `AESGCMSIVCipher` for authenticated
> encryption.

### Example 5: AES raw block (low-level)

```typescript
import { init, AES, randomBytes } from 'leviathan-crypto'
import { aesWasm } from 'leviathan-crypto/aes/embedded'

await init({ aes: aesWasm })

const cipher = new AES()
try {
	const key = randomBytes(32)          // AES-256
	cipher.loadKey(key)

	const plaintext  = new Uint8Array(16)
	crypto.getRandomValues(plaintext)
	const ciphertext = cipher.encryptBlock(plaintext)
	const decrypted  = cipher.decryptBlock(ciphertext)
	// decrypted is identical to plaintext
} finally {
	cipher.dispose()
}
```

---

## Error Conditions

| Condition | Error type | Message |
|-----------|-----------|---------|
| `init({ aes: ... })` not called before constructing any AES class | `Error` | `leviathan-crypto: call init({ aes: ... }) before using this class` |
| `AESCbc` constructed without `{ dangerUnauthenticated: true }` | `Error` | `leviathan-crypto: AESCbc is unauthenticated, use Seal with SerpentCipher or XChaCha20Cipher instead. To use AESCbc directly, pass { dangerUnauthenticated: true }.` |
| `AESCtr` constructed without `{ dangerUnauthenticated: true }` | `Error` | `leviathan-crypto: AESCtr is unauthenticated, use Seal with AESGCMSIVCipher, SerpentCipher, or XChaCha20Cipher instead. To use AESCtr directly, pass { dangerUnauthenticated: true }.` |
| Key not 16, 24, or 32 bytes (`AES.loadKey`) | `RangeError` | `AES.loadKey: key must be 16, 24, or 32 bytes (got N)` |
| Key not 16, 24, or 32 bytes (`AESCbc`/`AESCtr`/`AESGCM`) | `RangeError` | `AES key must be 16, 24, or 32 bytes (got N)` |
| Key not 16 or 32 bytes (`AESGCMSIV`) | `RangeError` | `AESGCMSIV key must be 16 or 32 bytes (got N); AES-192-GCM-SIV is not defined by RFC 8452` |
| Block not 16 bytes (`AES.encryptBlock`/`decryptBlock`) | `RangeError` | `block must be 16 bytes (got N)` |
| Nonce not 16 bytes (`AESCtr`) | `RangeError` | `AES CTR nonce must be 16 bytes (got N)` |
| IV not 16 bytes (`AESCbc`) | `RangeError` | `CBC IV must be 16 bytes (got N)` |
| Ciphertext zero-length, non-multiple-of-16, or PKCS7 invalid (`AESCbc.decrypt`) | `RangeError` | `invalid ciphertext` (same message for every failure mode) |
| IV less than 1 byte (`AESGCM.seal`) | `RangeError` | `GCM IV must be ≥ 1 byte` |
| IV exceeds 65536 bytes (`AESGCM.seal`) | `RangeError` | `GCM IV must be ≤ 65536 bytes (got N)` |
| AAD exceeds 65536 bytes (`AESGCM`) | `RangeError` | `GCM AAD must be ≤ 65536 bytes (got N)` |
| Plaintext exceeds 2^36 - 32 bytes (`AESGCM.seal`) | `RangeError` | `GCM plaintext must be ≤ 2^36 - 32 bytes (got N)` |
| Tag mismatch or any length violation (`AESGCM.open`) | `RangeError` | `authentication failed` (same message for every failure mode) |
| Nonce not 12 bytes (`AESGCMSIV`) | `RangeError` | `AESGCMSIV nonce must be 12 bytes (got N)` |
| Plaintext exceeds 65536 bytes (`AESGCMSIV`) | `RangeError` | `AESGCMSIV plaintext must be ≤ 65536 bytes (got N)` |
| AAD exceeds 65536 bytes (`AESGCMSIV`) | `RangeError` | `AESGCMSIV AAD must be ≤ 65536 bytes (got N)` |
| Tag mismatch or any length violation (`AESGCMSIV.open`) | `AuthenticationError` | `siv` |
| Tag mismatch (`AESGCMSIVCipher.openChunk`) | `AuthenticationError` | `aes-gcm-siv` |
| Method called after `dispose()` (`AESCbc`/`AESCtr`/`AESGCM`/`AESGCMSIV`) | `Error` | `<ClassName>: instance has been disposed` |
| `AESGenerator.generate()` key ≠ 32 bytes | `RangeError` | `AESGenerator: key must be 32 bytes (got N)` |
| `AESGenerator.generate()` counter ≠ 16 bytes | `RangeError` | `AESGenerator: counter must be 16 bytes (got N)` |
| `AESGenerator.generate()` n out of range | `RangeError` | `AESGenerator: n must be a non-negative safe integer <= 2^30 (got N)` |

---


## Cross-References

| Document | Description |
| -------- | ----------- |
| [index](./README.md) | Project Documentation index |
| [lexicon](./lexicon.md) | Glossary of cryptographic terms |
| [architecture](./architecture.md) | architecture overview, module relationships, buffer layouts, and build pipeline |
| [asm_aes](./asm_aes.md) | AES WASM implementation details, buffer layout, and SIMD architecture |
| [authenticated encryption](./aead.md) | `Seal`, `SealStream`, `OpenStream`: use `AESGCMSIVCipher` as the suite argument |
| [ciphersuite](./ciphersuite.md) | `AESGCMSIVCipher` reference: format enum, key derivation, commitment binding |
| [fortuna](./fortuna.md) | `Fortuna` CSPRNG with `AESGenerator` (Practical Cryptography §9.4) |
| [serpent](./serpent.md) | `SerpentCipher`: alternative `CipherSuite` for `Seal` and streaming |
| [chacha20](./chacha20.md) | `XChaCha20Cipher`: alternative `CipherSuite` for `Seal` and streaming |
| [sha2](./sha2.md) | HMAC-SHA-256 and HKDF used internally by `AESGCMSIVCipher` |
| [types](./types.md) | `Blockcipher`, `Streamcipher`, and `AEAD` interfaces |
| [utils](./utils.md) | `constantTimeEqual`, `wipe`, `randomBytes` used by AES wrappers |
