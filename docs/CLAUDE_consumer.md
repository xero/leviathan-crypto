# leviathan-crypto — AI Assistant Guide

This file ships with the package to help AI assistants use this library correctly.
Full API documentation is in the `docs/` directory alongside this file.

---

## What This Library Is

`leviathan-crypto` is a zero-dependency WebAssembly cryptography library for
TypeScript and JavaScript. All cryptographic computation runs in WASM, outside
the JavaScript JIT. The TypeScript layer provides the public API — input
validation, type safety, and ergonomics. It never implements cryptographic
algorithms itself.

---

## Critical: `init()` is required

**No class works before `init()` is called.** Calling any class before its
module is loaded throws immediately with a clear error. Call `init()` once at
startup, before any cryptographic operations.

```typescript
import { init, Serpent } from 'leviathan-crypto'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'
import { sha2Wasm }    from 'leviathan-crypto/sha2/embedded'

await init({ serpent: serpentWasm, sha2: sha2Wasm })
```

`init()` accepts a `Partial<Record<Module, WasmSource>>`. Each value is a
`WasmSource` — a gzip+base64 string, `URL`, `ArrayBuffer`, `Uint8Array`,
pre-compiled `WebAssembly.Module`, `Response`, or `Promise<Response>`.

The `/embedded` subpath exports are the simplest WasmSource: they are the
gzip+base64 blobs for each module, bundled with the package.

---

## Critical: call `dispose()` after use

Every class holds WASM memory containing key material. Call `dispose()` when
done — it zeroes that memory. Not calling `dispose()` leaks key material.

```typescript
const cipher = new XChaCha20Poly1305()
try {
    return cipher.encrypt(key, nonce, plaintext)
} finally {
    cipher.dispose()
}
```

---

## Critical: `decrypt()` throws on authentication failure — never returns null

All AEAD `decrypt()` methods throw if authentication fails. Do not check for a
null return — catch the exception.

```typescript
try {
    const plaintext = seal.decrypt(key, ciphertext)
} catch {
    // wrong key or tampered data
}
```

---

## Critical: subpath init function names

Each subpath export has its own module-specific init function — not `init()`.
These are only needed for tree-shakeable imports. The root barrel `init()` is
the normal path.

Each init function takes a single `WasmSource` argument. Use the module's
`/embedded` subpath to get the bundled blob as a ready-to-use WasmSource.

| Subpath | Init function | Embedded blob |
|---------|---------------|---------------|
| `leviathan-crypto/serpent` | `serpentInit(source)` | `leviathan-crypto/serpent/embedded` → `serpentWasm` |
| `leviathan-crypto/chacha20` | `chacha20Init(source)` | `leviathan-crypto/chacha20/embedded` → `chacha20Wasm` |
| `leviathan-crypto/sha2` | `sha2Init(source)` | `leviathan-crypto/sha2/embedded` → `sha2Wasm` |
| `leviathan-crypto/sha3` | `sha3Init(source)` | `leviathan-crypto/sha3/embedded` → `sha3Wasm` |
| `leviathan-crypto/keccak` | `keccakInit(source)` | `leviathan-crypto/keccak/embedded` → `keccakWasm` |
| `leviathan-crypto/kyber` | `kyberInit(source)` | `leviathan-crypto/kyber/embedded` → `kyberWasm` |

```typescript
// Tree-shakeable — loads only serpent WASM
import { serpentInit, Serpent } from 'leviathan-crypto/serpent'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'
await serpentInit(serpentWasm)
```

---

## Which module does each class require?

| Classes | Required modules |
|---------|-----------------|
| `Serpent`, `SerpentCtr`, `SerpentCbc`, `SerpentCipher` | `init({ serpent: serpentWasm, sha2: sha2Wasm })` |
| `SealStream`, `OpenStream`, `SerpentCipher` (when using SerpentCipher) | `init({ serpent: serpentWasm, sha2: sha2Wasm })` |
| `SealStream`, `OpenStream`, `XChaCha20Cipher` (when using XChaCha20Cipher) | `init({ chacha20: chacha20Wasm, sha2: sha2Wasm })` |
| `SealStreamPool` | depends on cipher: same modules as the cipher suite + `sha2` |
| `ChaCha20`, `Poly1305`, `ChaCha20Poly1305`, `XChaCha20Poly1305` | `init({ chacha20: chacha20Wasm })` |
| `SHA256`, `SHA384`, `SHA512`, `HMAC_SHA256`, `HMAC_SHA384`, `HMAC_SHA512`, `HKDF_SHA256`, `HKDF_SHA512` | `init({ sha2: sha2Wasm })` |
| `SHA3_224`, `SHA3_256`, `SHA3_384`, `SHA3_512`, `SHAKE128`, `SHAKE256` | `init({ sha3: sha3Wasm })` or `init({ keccak: keccakWasm })` — `'keccak'` is an alias for `'sha3'` |
| `MlKem512`, `MlKem768`, `MlKem1024` | `init({ kyber: kyberWasm, sha3: sha3Wasm })` — both modules required |
| `Fortuna` | `init({ serpent: serpentWasm, sha2: sha2Wasm })` |

---

## Recommended patterns

### Authenticated encryption (recommended default)

```typescript
import { init, Seal, SerpentCipher, randomBytes } from 'leviathan-crypto'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'
import { sha2Wasm }    from 'leviathan-crypto/sha2/embedded'

await init({ serpent: serpentWasm, sha2: sha2Wasm })

const key       = SerpentCipher.keygen()
const blob      = Seal.encrypt(SerpentCipher, key, plaintext)
const decrypted = Seal.decrypt(SerpentCipher, key, blob)
```

### Incremental streaming AEAD

Use when you cannot buffer the full message before encrypting.

```typescript
import { init, SealStream, OpenStream, SerpentCipher, randomBytes } from 'leviathan-crypto'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await init({ serpent: serpentWasm, sha2: sha2Wasm })

const key    = randomBytes(32)
const sealer = new SealStream(SerpentCipher, key)
const preamble = sealer.preamble        // 20 bytes — send first
const ct0      = sealer.push(chunk0)
const ct1      = sealer.push(chunk1)
const ctLast   = sealer.finalize(lastChunk)

const opener   = new OpenStream(SerpentCipher, key, preamble)
const pt0    = opener.pull(ct0)
const pt1    = opener.pull(ct1)
const ptLast = opener.finalize(ctLast)
```

### Length-prefixed streaming (for files and buffered transports)

Pass `{ framed: true }` to `SealStream` for self-delimiting `u32be` length-prefixed
framing. Use when chunks will be concatenated into a flat byte stream. Omit when the
transport frames messages itself (WebSocket, IPC).

```typescript
const sealer = new SealStream(SerpentCipher, key, { framed: true })
```

### XChaCha20-Poly1305

```typescript
import { init, XChaCha20Poly1305, randomBytes } from 'leviathan-crypto'
import { chacha20Wasm } from 'leviathan-crypto/chacha20/embedded'

await init({ chacha20: chacha20Wasm })

const aead      = new XChaCha20Poly1305()
const key       = randomBytes(32)
const nonce     = randomBytes(24)
const sealed    = aead.encrypt(key, nonce, plaintext, aad?)  // ciphertext || tag
const plaintext = aead.decrypt(key, nonce, sealed, aad?)     // throws on tamper
aead.dispose()
```

Note: `encrypt()` returns ciphertext with the 16-byte Poly1305 tag appended.
`decrypt()` expects the same concatenated format — not separate ciphertext and tag.

### Hashing

```typescript
import { init, SHA256, HMAC_SHA256 } from 'leviathan-crypto'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await init({ sha2: sha2Wasm })

const hasher = new SHA256()
const digest = hasher.hash(data)   // returns Uint8Array
hasher.dispose()

const mac = new HMAC_SHA256()
const tag = mac.hash(key, data)
mac.dispose()
```

### SHAKE (XOF — variable-length output)

```typescript
import { init, SHAKE128 } from 'leviathan-crypto'
import { sha3Wasm } from 'leviathan-crypto/sha3/embedded'

await init({ sha3: sha3Wasm })

const xof = new SHAKE128()
xof.absorb(data)
const out1 = xof.squeeze(32)   // first 32 bytes of output stream
const out2 = xof.squeeze(32)   // next 32 bytes — contiguous XOF stream
xof.dispose()
```

### ML-KEM post-quantum key encapsulation

```typescript
import { init, MlKem768 } from 'leviathan-crypto'
import { kyberWasm } from 'leviathan-crypto/kyber/embedded'
import { sha3Wasm } from 'leviathan-crypto/sha3/embedded'

await init({ kyber: kyberWasm, sha3: sha3Wasm })

const kem = new MlKem768()
const { encapsulationKey, decapsulationKey } = kem.keygen()

// Encapsulation (sender — public encapsulationKey only)
const { ciphertext, sharedSecret: senderSecret } = kem.encapsulate(encapsulationKey)

// Decapsulation (recipient — private decapsulationKey)
const recipientSecret = kem.decapsulate(decapsulationKey, ciphertext)

// senderSecret === recipientSecret (32 bytes)
kem.dispose()
```

Kyber classes require **both** `kyber` and `sha3` initialized. ML-KEM produces
a 32-byte shared secret suitable for use as a symmetric key.

### Fortuna CSPRNG

```typescript
import { init, Fortuna } from 'leviathan-crypto'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'
import { sha2Wasm }    from 'leviathan-crypto/sha2/embedded'

await init({ serpent: serpentWasm, sha2: sha2Wasm })

const fortuna = await Fortuna.create()   // static factory — not new Fortuna()
const bytes   = fortuna.get(32)
fortuna.stop()
```

---

## `SerpentCbc` arg order

IV is the **second** argument, not the third:

```typescript
cipher.encrypt(key, iv, plaintext)   // correct
cipher.decrypt(key, iv, ciphertext)  // correct
```

`SerpentCbc` is unauthenticated. Always pair with `HMAC_SHA256`
(Encrypt-then-MAC) or use `Seal` with `SerpentCipher` instead.

---

## Utilities (no `init()` required)

```typescript
import { hexToBytes, bytesToHex, randomBytes, constantTimeEqual, wipe, hasSIMD } from 'leviathan-crypto'

// available immediately — no await init() needed
const key  = randomBytes(32)
const hex  = bytesToHex(key)
const back = hexToBytes(hex)
const safe = constantTimeEqual(a, b)   // constant-time equality — never use ===
wipe(key)                               // zero a Uint8Array in place
```

`hasSIMD()` returns `true` if the runtime supports WebAssembly SIMD.
Serpent, ChaCha20, and Kyber modules all require SIMD — `init()` throws
a clear error on runtimes without support. SIMD has been a baseline
feature of all major browsers and runtimes since 2021. SHA-2 and SHA-3
modules run on any WASM-capable runtime.

---

## Full documentation

The complete API reference ships in `docs/` alongside this file:

| File | Contents |
|------|----------|
| `docs/serpent.md` | `SerpentCipher`, `Serpent`, `SerpentCtr`, `SerpentCbc` |
| `docs/chacha20.md` | `ChaCha20`, `Poly1305`, `ChaCha20Poly1305`, `XChaCha20Poly1305`, `XChaCha20Cipher` |
| `docs/sha2.md` | `SHA256`, `SHA384`, `SHA512`, `HMAC_SHA256`, `HMAC_SHA384`, `HMAC_SHA512`, `HKDF_SHA256`, `HKDF_SHA512` |
| `docs/sha3.md` | `SHA3_224`, `SHA3_256`, `SHA3_384`, `SHA3_512`, `SHAKE128`, `SHAKE256` |
| `docs/stream.md` | `Seal`, `SealStream`, `OpenStream`, `SealStreamPool`, `CipherSuite` |
| `docs/kyber.md` | `MlKem512`, `MlKem768`, `MlKem1024`, `KyberSuite` — ML-KEM (FIPS 203) API reference |
| `docs/fortuna.md` | `Fortuna` CSPRNG |
| `docs/init.md` | `init()` API, loading modes, subpath imports |
| `docs/utils.md` | Encoding helpers, `constantTimeEqual`, `wipe`, `randomBytes` |
| `docs/types.md` | `Hash`, `KeyedHash`, `Blockcipher`, `Streamcipher`, `AEAD` interfaces; `CipherSuite`, `DerivedKeys`, `SealStreamOpts`, `PoolOpts`, `WasmSource` |
| `docs/architecture.md` | Module structure, WASM layer, three-tier design |
