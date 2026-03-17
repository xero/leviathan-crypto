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
import { init, SerpentSeal } from 'leviathan-crypto'

await init(['serpent', 'sha2'])  // load only the modules you need
```

Available modules: `'serpent'`, `'chacha20'`, `'sha2'`, `'sha3'`

---

## Critical: call `dispose()` after use

Every class holds WASM memory containing key material. Call `dispose()` when
done — it zeroes that memory. Not calling `dispose()` leaks key material.

```typescript
const cipher = new SerpentSeal()
try {
    return cipher.encrypt(key, plaintext)
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

| Subpath | Init function |
|---------|---------------|
| `leviathan-crypto/serpent` | `serpentInit()` |
| `leviathan-crypto/chacha20` | `chacha20Init()` |
| `leviathan-crypto/sha2` | `sha2Init()` |
| `leviathan-crypto/sha3` | `sha3Init()` |

```typescript
// Tree-shakeable — loads only serpent WASM
import { serpentInit, SerpentSeal } from 'leviathan-crypto/serpent'
await serpentInit()
```

---

## Which module does each class require?

| Classes | `init()` call |
|---------|--------------|
| `SerpentSeal`, `SerpentStream`, `SerpentStreamPool`, `SerpentStreamSealer`, `SerpentStreamOpener`, `SerpentStreamEncoder`, `SerpentStreamDecoder`, `Serpent`, `SerpentCtr`, `SerpentCbc` | `init(['serpent', 'sha2'])` |
| `ChaCha20`, `Poly1305`, `ChaCha20Poly1305`, `XChaCha20Poly1305`, `XChaCha20Poly1305Pool` | `init(['chacha20'])` |
| `SHA256`, `SHA384`, `SHA512`, `HMAC_SHA256`, `HMAC_SHA384`, `HMAC_SHA512`, `HKDF_SHA256`, `HKDF_SHA512` | `init(['sha2'])` |
| `SHA3_224`, `SHA3_256`, `SHA3_384`, `SHA3_512`, `SHAKE128`, `SHAKE256` | `init(['sha3'])` |
| `Fortuna` | `init(['serpent', 'sha2'])` |

`Argon2id` is a separate subpath: `import { Argon2id } from 'leviathan-crypto/argon2id'`
It does **not** require `init()` — it uses its own WASM loader.
`'argon2id'` is **not** a valid module string for `init()`.

---

## Recommended patterns

### Authenticated encryption (recommended default)

```typescript
import { init, SerpentSeal, randomBytes } from 'leviathan-crypto'

await init(['serpent', 'sha2'])

const key = randomBytes(64)       // 64-byte key (encKey + macKey)
const seal = new SerpentSeal()
const ciphertext = seal.encrypt(key, plaintext)   // Serpent-CBC + HMAC-SHA256
const decrypted  = seal.decrypt(key, ciphertext)  // throws on tamper
seal.dispose()
```

### Incremental streaming AEAD

Use when you cannot buffer the full message before encrypting.

```typescript
import { init, SerpentStreamSealer, SerpentStreamOpener, randomBytes } from 'leviathan-crypto'

await init(['serpent', 'sha2'])

const key    = randomBytes(64)
const sealer = new SerpentStreamSealer(key, 65536)
const header = sealer.header()           // send to opener before any chunks

const chunk0 = sealer.seal(data0)        // exactly chunkSize bytes
const last   = sealer.final(tail)        // any size up to chunkSize; wipes key

const opener = new SerpentStreamOpener(key, header)
const pt0    = opener.open(chunk0)       // throws on auth failure
const ptLast = opener.open(last)
```

### Length-prefixed streaming (for files and buffered transports)

`SerpentStreamEncoder`/`SerpentStreamDecoder` wrap the sealer/opener with
`u32be` length-prefixed framing so chunk boundaries are self-delimiting.

```typescript
import { init, SerpentStreamEncoder, SerpentStreamDecoder, randomBytes } from 'leviathan-crypto'

await init(['serpent', 'sha2'])

const key     = randomBytes(64)
const encoder = new SerpentStreamEncoder(key, 65536)
const header  = encoder.header()

const frame0  = encoder.encode(data0)         // u32be(len) || sealed chunk
const last    = encoder.encodeFinal(tail)

const decoder = new SerpentStreamDecoder(key, header)
const chunks  = decoder.feed(frame0)          // returns Uint8Array[], throws on auth failure
```

### XChaCha20-Poly1305

```typescript
import { init, XChaCha20Poly1305, randomBytes } from 'leviathan-crypto'

await init(['chacha20'])

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

await init(['sha2'])

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

await init(['sha3'])

const xof = new SHAKE128()
xof.absorb(data)
const out1 = xof.squeeze(32)   // first 32 bytes of output stream
const out2 = xof.squeeze(32)   // next 32 bytes — contiguous XOF stream
xof.dispose()
```

### Fortuna CSPRNG

```typescript
import { init, Fortuna } from 'leviathan-crypto'

await init(['serpent', 'sha2'])

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
(Encrypt-then-MAC) or use `SerpentSeal` instead.

---

## Utilities (no `init()` required)

```typescript
import { hexToBytes, bytesToHex, randomBytes, constantTimeEqual, wipe } from 'leviathan-crypto'

// available immediately — no await init() needed
const key  = randomBytes(32)
const hex  = bytesToHex(key)
const back = hexToBytes(hex)
const safe = constantTimeEqual(a, b)   // constant-time equality — never use ===
wipe(key)                               // zero a Uint8Array in place
```

---

## Full documentation

The complete API reference ships in `docs/` alongside this file:

| File | Contents |
|------|----------|
| `docs/serpent.md` | `SerpentSeal`, `SerpentStream`, `SerpentStreamPool`, `SerpentStreamSealer`, `SerpentStreamOpener`, `SerpentStreamEncoder`, `SerpentStreamDecoder`, `Serpent`, `SerpentCtr`, `SerpentCbc` |
| `docs/chacha20.md` | `ChaCha20`, `Poly1305`, `ChaCha20Poly1305`, `XChaCha20Poly1305`, `XChaCha20Poly1305Pool` |
| `docs/sha2.md` | `SHA256`, `SHA384`, `SHA512`, `HMAC_SHA256`, `HMAC_SHA384`, `HMAC_SHA512`, `HKDF_SHA256`, `HKDF_SHA512` |
| `docs/sha3.md` | `SHA3_224`, `SHA3_256`, `SHA3_384`, `SHA3_512`, `SHAKE128`, `SHAKE256` |
| `docs/fortuna.md` | `Fortuna` CSPRNG |
| `docs/init.md` | `init()` API, loading modes, subpath imports |
| `docs/utils.md` | Encoding helpers, `constantTimeEqual`, `wipe`, `randomBytes` |
| `docs/types.md` | `Hash`, `KeyedHash`, `Blockcipher`, `Streamcipher`, `AEAD` interfaces |
| `docs/architecture.md` | Module structure, WASM layer, three-tier design |
