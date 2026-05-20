<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### Module Initialization and WASM Loading

Call `init()` before using any cryptographic class. It loads the WebAssembly modules that perform cryptographic work, caches them in memory, and makes them available to all wrapper classes.

> ### Table of Contents
> - [Overview](#overview)
> - [Security Notes](#security-notes)
> - [API Reference](#api-reference)
> - [Usage Examples](#usage-examples)
> - [Error Conditions](#error-conditions)

---

## Overview

leviathan-crypto runs all cryptographic computation inside WebAssembly modules.
These modules are not loaded automatically. You tell `init()` which modules you
need and provide a source for each one. After that, every class backed by those
modules is ready to use.

`init()` is idempotent. Calling it multiple times with the same module is safe.
It skips modules already loaded, so you can call `init()` in multiple places
without redundant work. It returns a Promise. Always `await` it before
constructing any class.

If you try to use a cryptographic class before calling `init()`, you get a clear
error telling you exactly which module to load.

---

## Security Notes

**WASM runs outside the JavaScript JIT.** Cryptographic code executes in
WebAssembly, which provides more predictable execution timing than optimized
JavaScript. This reduces the risk of timing side-channels introduced by the
JIT compiler.

**Each module gets its own linear memory.** Every WASM module receives a few
64 KB pages of independent memory (3 pages for most modules, 4 for AES due to
the GCM-SIV state). Key material in one module cannot be read by another.
There is no shared memory between modules.

**No silent auto-initialization.** Every wrapper class checks that its backing
module has been initialized. If it has not, the class throws immediately rather
than loading the module in the background. Initialization is explicit and
auditable.

---

## API Reference

### Types

```typescript
type Module = 'aes' | 'serpent' | 'chacha20' | 'sha2' | 'sha3' | 'keccak' | 'kyber' | 'mldsa' | 'slhdsa' | 'blake3' | 'curve25519' | 'p256'
```

The WASM module families. Each one backs a group of related classes.
`'keccak'` is an alias for `'sha3'`, same WASM binary, same instance slot.
`'ed25519'` and `'x25519'` are aliases for `'curve25519'`, same WASM
binary, same instance slot.

| Module | Classes it enables |
|---|---|
| `'aes'` | `AES`, `AESCbc`, `AESCtr`, `AESGCM`, `AESGCMSIV`, `AESGenerator` |
| `'aes'` + `'sha2'` | `AESGCMSIVCipher`, `Seal` (with `AESGCMSIVCipher`), `SealStream`, `OpenStream`, see [aead.md](./aead.md) |
| `'serpent'` | `Serpent`, `SerpentCbc`, `SerpentCtr` |
| `'serpent'` + `'sha2'` | `SerpentCipher`, `Seal` (with `SerpentCipher`), `SealStream`, `OpenStream`, see [aead.md](./aead.md) |
| `Fortuna` combinations | `Fortuna` accepts a `Generator` + `HashFn` pair. Valid module combinations: `'aes' + 'sha2'`, `'aes' + 'sha3'`, `'serpent' + 'sha2'`, `'serpent' + 'sha3'`, `'chacha20' + 'sha2'`, `'chacha20' + 'sha3'`. See [fortuna.md](./fortuna.md). |
| `'chacha20'` | `ChaCha20`, `ChaCha20Poly1305`, `XChaCha20Poly1305` |
| `'chacha20'` + `'sha2'` | `XChaCha20Cipher`, `Seal` (with `XChaCha20Cipher`), `SealStream`, `OpenStream`, see [aead.md](./aead.md) |
| `'sha2'` | `SHA256`, `SHA384`, `SHA512`, `HMAC` (SHA-2 based), `HKDF` |
| `'sha3'` / `'keccak'` | `SHA3_224`, `SHA3_256`, `SHA3_384`, `SHA3_512`, `SHAKE128`, `SHAKE256` |
| `'blake3'` | `BLAKE3`, `BLAKE3Stream`, `BLAKE3KeyedHash`, `BLAKE3KeyedHashStream`, `BLAKE3DeriveKey`, `BLAKE3DeriveKeyStream`, `BLAKE3OutputReader`, see [blake3.md](./blake3.md) |
| `'kyber'` + `'sha3'` | `MlKem512`, `MlKem768`, `MlKem1024`, see [kyber.md](./kyber.md) |
| `'kyber'` + `'sha3'` + inner cipher modules | `KyberSuite` (hybrid KEM+AEAD factory), see [kyber.md](./kyber.md) |
| `'mldsa'` + `'sha3'` | `MlDsa44`, `MlDsa65`, `MlDsa87` (pure ML-DSA + HashML-DSA with SHA-3 / SHAKE pre-hash), see [mldsa.md](./mldsa.md) |
| `'mldsa'` + `'sha3'` + `'sha2'` | `MlDsa44`, `MlDsa65`, `MlDsa87` (HashML-DSA with a SHA-2 family pre-hash; sha2 only required when `ph` is `'SHA2-*'`) |
| `'slhdsa'` (+`'sha3'` / `'sha2'` for prehash) | `SlhDsa128f`, `SlhDsa192f`, `SlhDsa256f` (pure SLH-DSA + HashSLH-DSA), see [slhdsa.md](./slhdsa.md) |
| `'curve25519'` / `'ed25519'` / `'x25519'` | `Ed25519` (pure + Ed25519ph), `X25519` (Curve25519 DH), see [ed25519.md](./ed25519.md) and [x25519.md](./x25519.md). `'ed25519'` and `'x25519'` are aliases that resolve to the underlying `curve25519` slot. |
| `'curve25519'` + `'sha2'` | `Ed25519PreHashSuite` (Ed25519ph via `Sign` / `SignStream` / `VerifyStream`) |
| `'p256'` | `EcdsaP256` (classical ECDSA over NIST P-256, FIPS 186-5 §6, hedged-or-deterministic K per RFC 6979 §3.2 + `draft-irtf-cfrg-det-sigs-with-noise-05`), see [ecdsa-p256.md](./ecdsa-p256.md) |
| `'p256'` + `'sha2'` | `EcdsaP256Suite` (via `Sign` / `SignStream` / `VerifyStream`) |

```typescript
type WasmSource = string | URL | ArrayBuffer | Uint8Array
               | WebAssembly.Module | Response | PromiseLike<WasmSource>
```

A value that resolves to a WASM binary. The loading strategy is inferred from
the type:

| Source type | What happens |
|---|---|
| `string` | Treated as a gzip+base64 embedded blob. Decoded and decompressed. |
| `URL` | Fetched with streaming compilation (`WebAssembly.compileStreaming`). |
| `ArrayBuffer` | Compiled directly via `WebAssembly.instantiate`. |
| `Uint8Array` | Compiled directly via `WebAssembly.instantiate`. |
| `WebAssembly.Module` | Already compiled. Instantiated immediately. |
| `Response` | Streaming compilation via `WebAssembly.instantiateStreaming`. |
| `PromiseLike<WasmSource>` | Awaited and re-dispatched by the resolved runtime type. |

Any `PromiseLike<WasmSource>` is accepted, `Promise<ArrayBuffer>`,
`Promise<Uint8Array>`, `Promise<string>`, a `fetch()` response promise, and
nested thenables up to depth 3 all resolve transparently. See
[loader.md](./loader.md) for details.

```typescript
type InitInput = Partial<Record<Module | 'ed25519' | 'x25519', WasmSource>>
```

The top-level `init()` parameter type. Each key is a module name (any
`Module` value plus the `'ed25519'` and `'x25519'` aliases); each value is
the `WasmSource` to load that module from. Keys are optional, only modules
present in the object are loaded. The two aliases resolve to the underlying
`curve25519` slot and are de-duped if given identical sources.

---

### Functions

#### init()

```typescript
async function init(sources: InitInput): Promise<void>
```

Initializes one or more WASM modules. Pass an object mapping module names to
their `WasmSource`. Only modules present in the object are loaded. Others are
left untouched.

---

#### Per-module init functions

Each module subpath exports its own init function for tree-shakeable imports.
These take a single `WasmSource` argument.

```typescript
async function aesInit(source: WasmSource): Promise<void>
async function serpentInit(source: WasmSource): Promise<void>
async function chacha20Init(source: WasmSource): Promise<void>
async function sha2Init(source: WasmSource): Promise<void>
async function sha3Init(source: WasmSource): Promise<void>
async function keccakInit(source: WasmSource): Promise<void>
async function kyberInit(source: WasmSource): Promise<void>
async function mldsaInit(source: WasmSource): Promise<void>
async function slhdsaInit(source: WasmSource): Promise<void>
async function blake3Init(source: WasmSource): Promise<void>
async function ed25519Init(source: WasmSource): Promise<void>  // alias for curve25519
async function x25519Init(source: WasmSource): Promise<void>   // alias for curve25519
async function ecdsaP256Init(source: WasmSource): Promise<void>
```

Each function initializes only its own WASM module, keeping other modules out
of your bundle.

---

#### Embedded subpath exports

The `/embedded` subpath for each module provides the gzip+base64 blob as a
ready-to-use `WasmSource`:

| Subpath | Export |
|---|---|
| `leviathan-crypto/aes/embedded` | `aesWasm` |
| `leviathan-crypto/serpent/embedded` | `serpentWasm` |
| `leviathan-crypto/chacha20/embedded` | `chacha20Wasm` |
| `leviathan-crypto/sha2/embedded` | `sha2Wasm` |
| `leviathan-crypto/sha3/embedded` | `sha3Wasm` |
| `leviathan-crypto/keccak/embedded` | `keccakWasm` |
| `leviathan-crypto/kyber/embedded` | `kyberWasm` |
| `leviathan-crypto/mldsa/embedded` | `mldsaWasm` |
| `leviathan-crypto/slhdsa/embedded` | `slhdsaWasm` |
| `leviathan-crypto/blake3/embedded` | `blake3Wasm` |
| `leviathan-crypto/ed25519/embedded` | `ed25519Wasm` (alias for `curve25519Wasm`) |
| `leviathan-crypto/x25519/embedded` | `x25519Wasm` (alias for `curve25519Wasm`) |
| `leviathan-crypto/ecdsa/embedded` | `p256Wasm` / `ecdsaP256Wasm` (both resolve to the same blob) |

`keccakWasm` and `sha3Wasm` are the same gzip+base64 blob. Both point to `sha3.wasm`.

> [!NOTE]
> `MlKem512`, `MlKem768`, and `MlKem1024` require both `kyber` and `sha3`
> (or `keccak`) to be initialized. The kyber module handles polynomial arithmetic.
> The sha3 module provides the Keccak sponge operations used for key generation
> and encapsulation.

> [!NOTE]
> `MlDsa44`, `MlDsa65`, and `MlDsa87` require both `mldsa` and `sha3` to be
> initialized. The mldsa module handles polynomial arithmetic, NTT, and
> rejection sampling. The sha3 module provides SHAKE128 (matrix expansion),
> SHAKE256 (noise expansion, masking, message representative, SampleInBall),
> and the SHA-3 fixed-output digests for HashML-DSA pre-hash.
>
> `sha2` is additionally required only when calling `signHash` /
> `verifyHash` with a SHA-2 family pre-hash (`'SHA2-224'`, `'SHA2-256'`,
> `'SHA2-384'`, `'SHA2-512'`, `'SHA2-512/224'`, `'SHA2-512/256'`).
> Pure ML-DSA and HashML-DSA with SHA-3 or SHAKE pre-hashes work with just
> `init({ mldsa, sha3 })`. Calling a SHA-2 pre-hash without sha2 initialized
> throws a clear error rather than silently misbehaving. See
> [mldsa.md](./mldsa.md).

---

#### isInitialized()

```typescript
function isInitialized(mod: Module): boolean
```

Returns `true` if the given module has been loaded and cached. Exported from
both `init.ts` and the root barrel.

> [!NOTE]
> `isInitialized` is a diagnostic indicator, not a control mechanism. Use
> `init()` to load modules. Do not guard calls on this value.

---

#### getInstance() `@internal`

```typescript
function getInstance(mod: Module): WebAssembly.Instance
```

Returns the cached WebAssembly instance for a module. Used internally by
wrapper classes. **Not exported from the `leviathan-crypto` root barrel**,
the wrapper classes consume it directly within the package. Documented here
for completeness; consumers do not normally need to call it.

Throws `'leviathan-crypto: call init({ <mod>: ... }) before using this class'`
if the module has not been initialized.

---

#### compileWasm() `@internal`

```typescript
async function compileWasm(source: WasmSource): Promise<WebAssembly.Module>
```

Compiles a `WasmSource` to a `WebAssembly.Module` without instantiating it.
Used by pool infrastructure to send compiled modules to workers. **Not
exported from the `leviathan-crypto` root barrel.** See
[loader.md](./loader.md) for details.

---

## Usage Examples

### Embedded init (most common)

The WASM binaries are bundled inside the package as gzip+base64 strings. Import
the blob from the module's `/embedded` subpath and pass it to `init()`.

```typescript
import { init } from 'leviathan-crypto'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'
import { sha2Wasm }    from 'leviathan-crypto/sha2/embedded'

await init({ serpent: serpentWasm, sha2: sha2Wasm })
```

### Per-module init (tree-shaking)

Use the subpath init function when you need one module and want the smallest
possible bundle:

```typescript
import { serpentInit } from 'leviathan-crypto/serpent'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'

await serpentInit(serpentWasm)
```

### ECDSA-P256 init

The `EcdsaP256` class and `EcdsaP256Suite` both need the `p256`
module; the suite additionally needs `sha2` for the TS-side
SHA-256 prehash. Pure-class callers who hand a pre-computed
digest to `EcdsaP256.sign(sk, pk, msgHash, rnd)` only need
`p256`.

```typescript
import { init }     from 'leviathan-crypto'
import { p256Wasm } from 'leviathan-crypto/ecdsa/embedded'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await init({ p256: p256Wasm, sha2: sha2Wasm })
```

Or via the subpath init for tree-shakeable imports:

```typescript
import { ecdsaP256Init } from 'leviathan-crypto/ecdsa'
import { p256Wasm }      from 'leviathan-crypto/ecdsa/embedded'

await ecdsaP256Init(p256Wasm)
```

The embedded subpath exports the same blob under two names
(`p256Wasm` matches the WASM module name; `ecdsaP256Wasm` reads
more naturally in the ecdsa subpath context).

### Keccak alias (for ML-KEM)

`'keccak'` is an alias for `'sha3'`. Both resolve to the same WASM binary and
the same instance slot. Use it when you want the semantically correct primitive
name for ML-KEM consumers:

```typescript
import { init } from 'leviathan-crypto'
import { keccakWasm } from 'leviathan-crypto/keccak/embedded'

await init({ keccak: keccakWasm })
// isInitialized('sha3') === true, same slot
// isInitialized('keccak') === true, alias resolves symmetrically
```

Or via the subpath directly:

```typescript
import { keccakInit, SHAKE128, SHA3_256 } from 'leviathan-crypto/keccak'
import { keccakWasm } from 'leviathan-crypto/keccak/embedded'

await keccakInit(keccakWasm)
```

### URL-based loading (CDN)

Pass a `URL` to fetch and compile the `.wasm` file via streaming compilation.
The server must respond with `Content-Type: application/wasm`.

```typescript
await init({ serpent: new URL('https://unpkg.com/leviathan-crypto/dist/serpent.wasm') })
```

### Pre-compiled module (edge runtimes)

If you have already compiled the binary, for example from a KV cache, pass the
`WebAssembly.Module` directly:

```typescript
const mod = await WebAssembly.compile(bytes)
await init({ serpent: mod })
```

### Checking initialization state

```typescript
import { isInitialized } from 'leviathan-crypto'

if (!isInitialized('sha2')) {
  // handle accordingly
}
```

---

## Error Conditions

| Situation | What happens |
|---|---|
| Using a class before calling `init()` | Throws: `"leviathan-crypto: call init({ ${mod}: ... }) before using this class"` |
| Invalid `WasmSource` (null, number, etc.) | Throws: `TypeError` with a descriptive message |
| Empty string source | Throws: `"leviathan-crypto: invalid WasmSource, empty string"` |
| Calling `init()` for an already-loaded module | No error. Module is silently skipped. |

---


## Cross-References

| Document | Description |
| -------- | ----------- |
| [index](./README.md) | Project Documentation index |
| [architecture](./architecture.md) | Repository structure, build and CI, WASM modules, public API, test suite, and security posture |
| [loader](./loader.md) | WASM binary loading strategies (internal details) |
| [wasm](./wasm.md) | WebAssembly primer: modules, instances, memory, and the init gate |

