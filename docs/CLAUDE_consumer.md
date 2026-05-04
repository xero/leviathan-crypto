# leviathan-crypto — AI Assistant Guide

> [!NOTE]
> This file ships with the package to help AI assistants use this library correctly. Full API documentation is in the `docs/` directory alongside this file.

> ### Table of Contents
> - [What This Library Is](#what-this-library-is)
> - [Critical: stateful classes hold exclusive access](#critical-stateful-classes-hold-exclusive-access)
> - [Critical: `init()` is required](#critical-init-is-required)
> - [Critical: call `dispose()` after use](#critical-call-dispose-after-use)
> - [Critical: `decrypt()` throws on authentication failure](#critical-decrypt-throws-on-authentication-failure--never-returns-null)
> - [Critical: subpath init function names](#critical-subpath-init-function-names)
> - [Which module does each class require?](#which-module-does-each-class-require)
> - [Recommended patterns](#recommended-patterns)
> - [`SerpentCbc` arg order](#serpentcbc-arg-order)
> - [Utilities (no `init()` required)](#utilities-no-init-required)
> - [Full documentation](#full-documentation)

---

## What This Library Is

`leviathan-crypto` is a zero-dependency WebAssembly cryptography library for
TypeScript and JavaScript. All cryptographic computation runs in WASM, outside
the JavaScript JIT. The TypeScript layer provides the public API: input
validation, type safety, and ergonomics. It never implements cryptographic
algorithms itself.

---

## Critical: stateful classes hold exclusive access

> [!CAUTION]
> Stateful classes (`SHAKE128`, `SHAKE256`, `ChaCha20`, `SerpentCtr`,
> `SerpentCbc`) hold exclusive access to their WASM module for their entire
> lifetime. Construct, use, `dispose()` — in that order. Attempting to
> construct a second stateful instance on the same module throws. Atomic
> one-shot classes (`SHA256`, `SHA3_*`, `HMAC_*`, `Poly1305`, AEAD classes)
> also throw if the module is held by a stateful class. Pool workers are
> unaffected (each worker has its own WASM instance).

Every TS wrapper in a given WASM module shares one `WebAssembly.Instance` and
therefore one linear memory. A runtime exclusivity guard prevents two stateful
instances from silently clobbering each other's state:

```typescript
const a = new SHAKE128()
a.absorb(msg1)
const b = new SHAKE128()   // throws — a still owns the 'sha3' module
a.squeeze(32)
a.dispose()                // release
const c = new SHAKE128()   // ok
```

The same applies across class boundaries on the same module — e.g. a live
`SerpentCbc` blocks `new SerpentCtr()`, `new Serpent()`, and
`Seal.encrypt(SerpentCipher, ...)` until `dispose()`. Always wrap stateful
use in `try { ... } finally { x.dispose() }`.

The exclusivity guard also fires on atomic method calls (`SHA256.hash`,
`HMAC_SHA256.hash`, `Poly1305.mac`, `Serpent.encryptBlock`, `XChaCha20Cipher.sealChunk`,
and their peers) when another stateful instance holds the same WASM module.
This protects pre-existing long-lived atomic instances from having their
WASM state silently clobbered by a later-constructed stateful user. If you
hold a `Fortuna` instance backed by `SerpentGenerator` and also want to use `SerpentCtr`/`SerpentCbc`, or one backed by `ChaCha20Generator` while also using `ChaCha20Poly1305`/`XChaCha20Poly1305`, you must `dispose()` one before operating the other. The library will throw a clear error rather than silently corrupting state.

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
`WasmSource`: a gzip+base64 string, `URL`, `ArrayBuffer`, `Uint8Array`,
pre-compiled `WebAssembly.Module`, `Response`, or `Promise<Response>`.

The `/embedded` subpath exports are the simplest WasmSource: they are the
gzip+base64 blobs for each module, bundled with the package.

---

## Critical: call `dispose()` after use

Every class holds WASM memory containing key material. Call `dispose()` when
done; it zeroes that memory. Not calling `dispose()` leaks key material.

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
null return; catch the exception.

```typescript
try {
    const plaintext = seal.decrypt(key, ciphertext)
} catch {
    // wrong key or tampered data
}
```

---

## Probing initialization state

`isInitialized(mod)` is the canonical readiness probe. Pass any module name
(`'serpent'`, `'chacha20'`, `'sha2'`, `'sha3'`, `'keccak'`, `'kyber'`) and
get back a boolean. Useful for tests, diagnostic gates, and lazy-loading
flows. It is a diagnostic indicator, not a control mechanism — for normal
flows just call `init()` and let it short-circuit on already-loaded modules.

```typescript
import { isInitialized } from 'leviathan-crypto'

if (!isInitialized('sha2')) {
    await init({ sha2: sha2Wasm })
}
```

The five per-module `_<module>Ready()` probes that existed in 2.1.x were
removed in 2.1.1 in favour of this single helper. See `docs/init.md` for
the full reference.

---

## Critical: subpath init function names

Each subpath export has its own module-specific init function, not `init()`.
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
| `Fortuna` | `init(...)` with one cipher module (`serpent` or `chacha20`) plus one hash module (`sha2` or `sha3`). All four combinations are valid. |
| `KDFChain`, `ratchetInit`, `ratchetReady`, `SkippedKeyStore` | `init({ sha2: sha2Wasm })` |
| `kemRatchetEncap`, `kemRatchetDecap`, `RatchetKeypair` | `init({ sha2: sha2Wasm, kyber: kyberWasm, sha3: sha3Wasm })` |

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
`decrypt()` expects the same concatenated format, not separate ciphertext and tag.

> [!CAUTION]
> **Strict single-use on `encrypt()`.** `ChaCha20Poly1305.encrypt()` and
> `XChaCha20Poly1305.encrypt()` are terminal on **any** throw — including
> `RangeError` on key/nonce length. A retry on the same instance always
> raises the single-use guard, never a fresh length error. Always allocate
> a new AEAD per message. This tightens the 2.0-beta semantics where
> length-validation throws were recoverable.
>
> **`SealStream` / `OpenStream` have a `'failed'` terminal state for crypto
> failures.** Crypto-path throws from `push()`, `pull()`, or `finalize()`
> (auth failure, WASM errors, cipher exceptions) wipe derived keys and
> transition the stream to `'failed'`. Subsequent operations and `seek()`
> throw with `'failed'` in the message. `dispose()` on a `'failed'` stream
> is a no-op.
>
> **Argument errors are non-terminal on both `SealStream` and `OpenStream`.**
> `push()` / `finalize()` throwing `RangeError` for a chunk larger than
> `chunkSize` does NOT wipe keys or enter `'failed'`. Symmetrically,
> `pull()` / `finalize()` throwing `RangeError` for a too-short chunk,
> an oversize chunk, or a framed length-prefix mismatch does NOT wipe keys
> or enter `'failed'` either. The stream stays in `'ready'` and accepts a
> corrected retry. Only auth failures from the crypto path transition to
> `'failed'`. Validation errors depend only on attacker-observable input
> lengths, so this distinction creates no cryptographic oracle.
>
> **`SealStreamPool.seal()` is terminal on any throw.** Worker errors,
> auth failures, output-size overflows, or any other rejection kill the
> pool (`pool is dead`, keys wiped). Construct a new pool to continue.
>
> **`OpenStream.seek` is forward-only and fully validates before mutating.**
> Backward seeks (`index < this.counter`) throw a `RangeError` with
> `'forward-only'` in the message. Indices above `Number.MAX_SAFE_INTEGER`
> throw without mutating `counter`, so the stream stays usable. Construct
> a fresh `OpenStream` from the same preamble to restart from the
> beginning.
>
> **Loader accepts any `PromiseLike<WasmSource>`.** `Promise<Response>`,
> `Promise<ArrayBuffer>`, `Promise<Uint8Array>`, and `Promise<string>`
> (gzip+base64 blob) all work — the loader resolves the thenable and
> re-dispatches by the resolved runtime type. Nesting is capped at depth
> 3; deeper chains throw `TypeError: thenable nesting too deep (max 3)`.

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

- `encapsulate(ek)` and `decapsulate(dk, c)` now throw `RangeError` on FIPS 203
  §7.2/§7.3 validation failure. This is a breaking change from 1.x. Callers that
  want to probe a key without triggering an exception can still call the public
  `checkEncapsulationKey(ek)` / `checkDecapsulationKey(dk)` boolean methods. The
  §7.3 throw is a local-integrity check on key material (ML-KEM assumes `dk` is
  recipient-controlled local storage) and is distinct from the FO transform's
  implicit-rejection path for tampered ciphertext, which returns a pseudorandom
  shared secret rather than throwing.

### Fortuna CSPRNG

`Fortuna.create()` requires explicit `generator` and `hash` parameters. There are no defaults.

```typescript
import { init, Fortuna } from 'leviathan-crypto'
import { ChaCha20Generator } from 'leviathan-crypto/chacha20'
import { SHA256Hash } from 'leviathan-crypto/sha2'
import { chacha20Wasm } from 'leviathan-crypto/chacha20/embedded'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await init({ chacha20: chacha20Wasm, sha2: sha2Wasm })
const fortuna = await Fortuna.create({ generator: ChaCha20Generator, hash: SHA256Hash })
const bytes   = fortuna.get(32)
fortuna.stop()
```

Substitute `SerpentGenerator` for `ChaCha20Generator`, or `SHA3_256Hash` for `SHA256Hash`, to use other primitive combinations. Match the `init()` modules to whichever pair you pick.

### Sparse Post-Quantum Ratchet (KDF layer only)

```typescript
import { init, MlKem768, ratchetInit, kemRatchetEncap, kemRatchetDecap, KDFChain } from 'leviathan-crypto'
import { sha2Wasm }  from 'leviathan-crypto/sha2/embedded'
import { kyberWasm } from 'leviathan-crypto/kyber/embedded'
import { sha3Wasm }  from 'leviathan-crypto/sha3/embedded'

await init({ sha2: sha2Wasm, kyber: kyberWasm, sha3: sha3Wasm })

const kem = new MlKem768()
const { encapsulationKey: bobEk, decapsulationKey: bobDk } = kem.keygen()

// Both parties derive initial keys from a shared secret
const alice = ratchetInit(sharedSecret)
const bob   = ratchetInit(sharedSecret)

// Alice performs a KEM ratchet step; kemCt goes in the message header
const aliceEpoch = kemRatchetEncap(kem, alice.nextRootKey, bobEk)

// Bob decapsulates after receiving kemCt. Pass bobEk as ownEk — both sides
// bind (peerEk, kemCt, context) into HKDF info with u32be length prefixes.
const bobEpoch = kemRatchetDecap(kem, bob.nextRootKey, bobDk, aliceEpoch.kemCt, bobEk)

// Both construct KDFChains and derive per-message keys
const aliceSend = new KDFChain(aliceEpoch.sendChainKey)
const bobRecv   = new KDFChain(bobEpoch.recvChainKey)
const msgKey    = aliceSend.step()   // alice encrypts; bob decrypts with bobRecv.step()
aliceSend.dispose()
bobRecv.dispose()
kem.dispose()
```

Additional ratchet exports:

- `SkippedKeyStore` — MKSKIPPED cache (DR spec §3.2/§3.5). `resolve(chain, counter)` returns a `ResolveHandle` — call `handle.commit()` on successful decrypt (wipes the key) and `handle.rollback()` on auth failure (returns the key to the store so a later legitimate delivery at the same counter can still decrypt). Double-settle throws; accessing `handle.key` after settling throws. Split budgets: `maxCacheSize` (default 100) bounds memory, `maxSkipPerResolve` (default 50) bounds per-message HKDF work. Legacy `{ ceiling: N }` still accepted — sets both. `advanceToBoundary(chain, pn)` for epoch transitions; `wipeAll()` on teardown. Requires `sha2`. **Breaking change from 1.x and 2.0-beta:** `resolve` used to return a raw key with delete-on-retrieval semantics.
- `RatchetKeypair` — single-use ek/dk wrapper; `new RatchetKeypair(kem)` generates a keypair, `decap(kem, rk, kemCt)` decapsulates exactly once then wipes the dk, `dispose()` is idempotent. Requires `sha2`, `kyber`, `sha3`.
- `RatchetMessageHeader` — interface `{ epoch, counter, pn?, kemCt? }`; `pn` and `kemCt` present only on the first message of a new epoch.
- `KDFChain.stepWithCounter()` — returns `{ key, counter }` atomically; eliminates the separate `.n` read after `step()`.

Idiomatic `resolve` usage:

```typescript
const h = store.resolve(chain, counter)
try {
    const plaintext = Seal.decrypt(cipher, h.key, ciphertext)
    h.commit()
    return plaintext
} catch (e) {
    h.rollback()
    throw e
}
```

See [docs/ratchet.md](./ratchet.md) for the full API reference including all
error conditions, the A2B direction split, bilateral exchange, group usage,
and context-based session separation.

---

## `SerpentCbc` arg order

IV is the **second** argument, not the third:

```typescript
cipher.encrypt(key, iv, plaintext)   // correct
cipher.decrypt(key, iv, ciphertext)  // correct
```

`SerpentCbc` is unauthenticated. Always pair with `HMAC_SHA256`
(Encrypt-then-MAC) or use `Seal` with `SerpentCipher` instead.

`SerpentCbc.decrypt()` throws a single generic `RangeError('invalid ciphertext')`
for every failure mode (empty input, non-multiple-of-16 length, any PKCS7 padding
mismatch) and validates the trailing 16 bytes branch-free. This closes the
Vaudenay 2002 padding-oracle surface on `{ dangerUnauthenticated: true }` callers,
but it is **not a substitute for authentication**. Power users must still apply
Encrypt-then-MAC with `HMAC_SHA256` and verify the tag with `constantTimeEqual`
before calling `decrypt()` — the CT-safe padding check only prevents one class
of leakage, not forgery.

---

## Utilities (no `init()` required)

```typescript
import { hexToBytes, bytesToHex, randomBytes, constantTimeEqual, wipe, hasSIMD } from 'leviathan-crypto'

// available immediately — no await init() needed
const key  = randomBytes(32)
const hex  = bytesToHex(key)
const back = hexToBytes(hex)
const safe = constantTimeEqual(a, b)   // constant-time equality (branch-free SIMD tail, no post-loop conditional on secret bits) — never use ===
wipe(key)                               // zero a Uint8Array in place
```

`hasSIMD()` returns `true` if the runtime supports WebAssembly SIMD.
Serpent, ChaCha20, and Kyber modules all require SIMD; `init()` throws
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
| `docs/aead.md` | `Seal`, `SealStream`, `OpenStream`, `SealStreamPool`, `CipherSuite` |
| `docs/kyber.md` | `MlKem512`, `MlKem768`, `MlKem1024`, `KyberSuite` — ML-KEM (FIPS 203) API reference |
| `docs/fortuna.md` | `Fortuna` CSPRNG |
| `docs/init.md` | `init()` API, loading modes, subpath imports |
| `docs/utils.md` | Encoding helpers, `constantTimeEqual`, `wipe`, `randomBytes` |
| `docs/types.md` | `Hash`, `KeyedHash`, `Blockcipher`, `Streamcipher`, `AEAD` interfaces; `CipherSuite`, `DerivedKeys`, `SealStreamOpts`, `PoolOpts`, `WasmSource` |
| `docs/architecture.md` | Module structure, WASM layer, three-tier design |
