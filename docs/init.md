# Module Initialization and WASM Loading

> [!IMPORTANT]
> Call `init()` before using any cryptographic class. It loads the WebAssembly
> modules that perform cryptographic work, caches them in memory, and makes them
> available to all wrapper classes.

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

**Each module gets its own linear memory.** Every WASM module receives 3 pages
(192 KB) of independent memory. Key material in one module cannot be read by
another. There is no shared memory between modules.

**No silent auto-initialization.** Every wrapper class checks that its backing
module has been initialized. If it has not, the class throws immediately rather
than loading the module in the background. Initialization is explicit and
auditable.

---

## API Reference

### Types

```typescript
type Module = 'serpent' | 'chacha20' | 'sha2' | 'sha3' | 'keccak' | 'kyber'
```

The WASM module families. Each one backs a group of related classes.
`'keccak'` is an alias for `'sha3'` — same WASM binary, same instance slot.

| Module | Classes it enables |
|---|---|
| `'serpent'` | `Serpent`, `SerpentCbc`, `SerpentCtr` |
| `'serpent'` + `'sha2'` | `SerpentCipher`, `Seal` (with `SerpentCipher`), `SealStream`, `OpenStream`, `Fortuna` — see [sealing.md](./sealing.md) |
| `'chacha20'` | `ChaCha20`, `ChaCha20Poly1305`, `XChaCha20Poly1305` |
| `'chacha20'` + `'sha2'` | `XChaCha20Cipher`, `Seal` (with `XChaCha20Cipher`), `SealStream`, `OpenStream` — see [sealing.md](./sealing.md) |
| `'sha2'` | `SHA256`, `SHA384`, `SHA512`, `HMAC` (SHA-2 based), `HKDF` |
| `'sha3'` / `'keccak'` | `SHA3_224`, `SHA3_256`, `SHA3_384`, `SHA3_512`, `SHAKE128`, `SHAKE256` |
| `'kyber'` | `MlKem512`, `MlKem768`, `MlKem1024` (also requires `'sha3'`) — see [kyber.md](./kyber.md) |
| `'kyber'` + `'sha3'` + inner cipher modules | `KyberSuite`, `MlKem512`, `MlKem768`, `MlKem1024` — see [kyber.md](./kyber.md) |

```typescript
type WasmSource = string | URL | ArrayBuffer | Uint8Array
               | WebAssembly.Module | Response | Promise<Response>
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
| `Response` / `Promise<Response>` | Streaming compilation via `WebAssembly.instantiateStreaming`. |

---

### Functions

#### init()

```typescript
async function init(
  sources: Partial<Record<Module, WasmSource>>,
): Promise<void>
```

Initializes one or more WASM modules. Pass an object mapping module names to
their `WasmSource`. Only modules present in the object are loaded. Others are
left untouched.

---

#### Per-module init functions

Each module subpath exports its own init function for tree-shakeable imports.
These take a single `WasmSource` argument.

```typescript
async function serpentInit(source: WasmSource): Promise<void>
async function chacha20Init(source: WasmSource): Promise<void>
async function sha2Init(source: WasmSource): Promise<void>
async function sha3Init(source: WasmSource): Promise<void>
async function keccakInit(source: WasmSource): Promise<void>
async function kyberInit(source: WasmSource): Promise<void>
```

Each function initializes only its own WASM module, keeping other modules out
of your bundle.

---

#### Embedded subpath exports

The `/embedded` subpath for each module provides the gzip+base64 blob as a
ready-to-use `WasmSource`:

| Subpath | Export |
|---|---|
| `leviathan-crypto/serpent/embedded` | `serpentWasm` |
| `leviathan-crypto/chacha20/embedded` | `chacha20Wasm` |
| `leviathan-crypto/sha2/embedded` | `sha2Wasm` |
| `leviathan-crypto/sha3/embedded` | `sha3Wasm` |
| `leviathan-crypto/keccak/embedded` | `keccakWasm` |
| `leviathan-crypto/kyber/embedded` | `kyberWasm` |

`keccakWasm` and `sha3Wasm` are the same gzip+base64 blob. Both point to `sha3.wasm`.

> [!NOTE]
> `MlKem512`, `MlKem768`, and `MlKem1024` require both `kyber` and `sha3`
> (or `keccak`) to be initialized. The kyber module handles polynomial arithmetic.
> The sha3 module provides the Keccak sponge operations used for key generation
> and encapsulation.

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

#### getInstance()

```typescript
function getInstance(mod: Module): WebAssembly.Instance
```

Returns the cached WebAssembly instance for a module. Used internally by
wrapper classes. You do not normally need to call this yourself.

Throws `'leviathan-crypto: call init({ <mod>: ... }) before using this class'`
if the module has not been initialized.

---

#### compileWasm()

```typescript
async function compileWasm(source: WasmSource): Promise<WebAssembly.Module>
```

Compiles a `WasmSource` to a `WebAssembly.Module` without instantiating it.
Used by pool infrastructure to send compiled modules to workers. See
[loader.md](./loader.md) for details.

---

#### _resetForTesting()

```typescript
function _resetForTesting(): void
```

Clears all cached WASM instances. Testing utility only. Do not use in
production code.

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

### Keccak alias (for ML-KEM)

`'keccak'` is an alias for `'sha3'`. Both resolve to the same WASM binary and
the same instance slot. Use it when you want the semantically correct primitive
name for ML-KEM consumers:

```typescript
import { init } from 'leviathan-crypto'
import { keccakWasm } from 'leviathan-crypto/keccak/embedded'

await init({ keccak: keccakWasm })
// isInitialized('sha3') === true — same slot
// isInitialized('keccak') === true — alias resolves symmetrically
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

If you have already compiled the binary such as from a KV cache, pass the
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
| Empty string source | Throws: `"leviathan-crypto: invalid WasmSource — empty string"` |
| Calling `init()` for an already-loaded module | No error. Module is silently skipped. |

---

> ## Cross-References
>
> - [index](./README.md) — Project Documentation index
> - [architecture](./architecture.md) — architecture overview, module relationships, buffer layouts, and build pipeline
> - [loader](./loader.md) — WASM binary loading strategies (internal details)
> - [wasm](./wasm.md) — WebAssembly primer: modules, instances, memory, and the init gate
