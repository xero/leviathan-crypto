# Module Initialization and WASM Loading

> [!IMPORTANT]
> The `init()` function is the entry point for leviathan-crypto. You must call it
> before using any cryptographic class. It loads the WebAssembly modules that
> perform the actual cryptographic work, caches them in memory, and makes them
> available to all wrapper classes.

## Overview

leviathan-crypto runs all cryptographic computation inside WebAssembly modules.
These modules are not available automatically, they need to be loaded and
compiled before any cryptographic class (`Serpent`, `SHA256`, `ChaCha20`, etc.)
can be used.

`init()` handles this process for you. You tell it which modules you need and
provide a source for each one. After that, every class backed by those modules
is ready to use.

Key properties:

- **Required before use.** If you try to create a cryptographic class before
  calling `init()`, you will get a clear error telling you what to do.
- **Source-driven loading.** Pass a `WasmSource` for each module you need.
  The loading strategy is inferred from the source type -- no mode string.
- **Idempotent.** Calling `init()` multiple times with the same module is
  safe, it skips modules that are already loaded. This means you can call
  `init()` in multiple places in your application without worrying about
  redundant work.
- **Async.** `init()` returns a Promise. Use `await` or `.then()` before
  proceeding.

---

## Security Notes

- **WASM runs outside the JavaScript JIT.** Cryptographic code executes in
  WebAssembly, which provides more predictable execution timing compared to
  optimized JavaScript. This reduces the risk of timing side-channels
  introduced by the JIT compiler.
- **Independent memory per module.** Each WASM module gets its own linear
  memory (3 pages, 192 KB). Key material loaded into one module's memory
  cannot be read by another module. There is no shared memory between modules.
- **No silent auto-initialization.** Every wrapper class checks that its
  backing module has been initialized. If it hasn't, the class throws an
  error immediately rather than silently loading the module in the
  background. This makes initialization explicit and auditable.

---

## API Reference

### Types

```typescript
type Module = 'serpent' | 'chacha20' | 'sha2' | 'sha3'
```

The four WASM module families. Each one backs a group of related classes:

| Module                  | Classes it enables                                                               |
| ----------------------- | -------------------------------------------------------------------------------- |
| `'serpent'`             | `Serpent`, `SerpentCbc`, `SerpentCtr`                                            |
| `'serpent'` + `'sha2'`  | `SerpentSeal`, `SerpentCipher`                                                   |
| `'chacha20'`            | `ChaCha20`, `ChaCha20Poly1305`, `XChaCha20Poly1305`, `XChaCha20Seal`             |
| `'chacha20'` + `'sha2'` | `XChaCha20Cipher` (stream layer requires sha2 for HKDF key derivation)           |
| `'sha2'`                | `SHA256`, `SHA384`, `SHA512`, `HMAC` (SHA-2 based), `HKDF`                       |
| `'sha3'`                | `SHA3`, `SHAKE128`, `SHAKE256`                                                   |
| `'serpent'` + `'sha2'`  | `Fortuna`                                                                        |

```typescript
type WasmSource = string | URL | ArrayBuffer | Uint8Array
               | WebAssembly.Module | Response | Promise<Response>
```

A value that resolves to a WASM binary. The loading strategy is inferred
from the type:

| Source type                      | What happens                                                         |
| -------------------------------- | -------------------------------------------------------------------- |
| `string`                         | Treated as a gzip+base64 embedded blob. Decoded and decompressed.    |
| `URL`                            | Fetched with streaming compilation (`WebAssembly.compileStreaming`). |
| `ArrayBuffer`                    | Compiled directly via `WebAssembly.instantiate`.                     |
| `Uint8Array`                     | Compiled directly via `WebAssembly.instantiate`.                     |
| `WebAssembly.Module`             | Already compiled. Instantiated immediately.                          |
| `Response` / `Promise<Response>` | Streaming compilation via `WebAssembly.instantiateStreaming`.        |

---

### Functions

#### `init(sources)` -- public API (exported from root barrel)

```typescript
async function init(
  sources: Partial<Record<Module, WasmSource>>,
): Promise<void>
```

Initializes one or more WASM modules. Pass an object mapping module names to
their `WasmSource`. Only modules present in the object are loaded; others are
left untouched.

---

#### Per-module init functions

Each module subpath exports its own init function for consumers who want
tree-shakeable imports. These take a single `WasmSource` argument.

```typescript
async function serpentInit(source: WasmSource): Promise<void>
async function chacha20Init(source: WasmSource): Promise<void>
async function sha2Init(source: WasmSource): Promise<void>
async function sha3Init(source: WasmSource): Promise<void>
```

Each function initializes only its own WASM module. This avoids pulling the
other three modules into the bundle, enabling tree-shaking.

---

#### Embedded subpath exports

The `/embedded` subpath for each module provides the gzip+base64 blob as a
ready-to-use `WasmSource`:

| Subpath                              | Export         |
| ------------------------------------ | -------------- |
| `leviathan-crypto/serpent/embedded`  | `serpentWasm`  |
| `leviathan-crypto/chacha20/embedded` | `chacha20Wasm` |
| `leviathan-crypto/sha2/embedded`     | `sha2Wasm`     |
| `leviathan-crypto/sha3/embedded`     | `sha3Wasm`     |

---

#### `getInstance(mod)`

```typescript
function getInstance(mod: Module): WebAssembly.Instance
```

Returns the cached WebAssembly instance for a module. This is used internally
by wrapper classes, you do not normally need to call it yourself.

**Throws:**
`'leviathan-crypto: call init({ <mod>: ... }) before using this class'` if
the module has not been initialized.

---

#### `isInitialized(mod)`

```typescript
function isInitialized(mod: Module): boolean
```

Returns `true` if the given module has been loaded and cached (read-only).
Exported from both `init.ts` and the root barrel (`src/ts/index.ts`).

> [!NOTE]
> `isInitialized` is a diagnostic indicator only -- not a control mechanism.
> Use `init()` to initialize modules; do not guard calls on this value.

---

#### `compileWasm(source)`

```typescript
async function compileWasm(source: WasmSource): Promise<WebAssembly.Module>
```

Compiles a `WasmSource` to a `WebAssembly.Module` without instantiating it.
Used by pool infrastructure to send compiled modules to workers. See
[loader.md](./loader.md) for details.

---

#### `_resetForTesting()`

```typescript
function _resetForTesting(): void
```

Clears all cached WASM instances. This is a testing utility, it allows test
suites to reset the initialization state between test runs. Do not use this in
production code.

---

## Usage Examples

### Embedded init (most common)

This is the recommended approach for most applications. The WASM binaries are
bundled inside the package as gzip+base64 strings. Import the blob from the
module's `/embedded` subpath and pass it to `init()`.

```typescript
import { init } from 'leviathan-crypto'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await init({ serpent: serpentWasm, sha2: sha2Wasm })
```

### Per-module init (tree-shaking)

Use the subpath init function when you only need one module and want the
smallest possible bundle:

```typescript
import { serpentInit } from 'leviathan-crypto/serpent'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'

await serpentInit(serpentWasm)
```

### URL-based (CDN)

Pass a `URL` to fetch and compile the `.wasm` file via streaming compilation.
The server must respond with `Content-Type: application/wasm`.

```typescript
await init({ serpent: new URL('https://unpkg.com/leviathan-crypto/dist/serpent.wasm') })
```

### Pre-compiled module (edge runtimes)

If you have already compiled the binary (e.g. cached in a KV store), pass the
`WebAssembly.Module` directly:

```typescript
const mod = await WebAssembly.compile(bytes)
await init({ serpent: mod })
```

### Checking if a module is initialized

```typescript
import { isInitialized } from 'leviathan-crypto'

if (!isInitialized('sha2')) {
  // handle accordingly
}
```

---

## Error Conditions

| Situation                                     | What happens                                                                     |
|-----------------------------------------------|----------------------------------------------------------------------------------|
| Using a class before calling `init()`         | Throws: `"leviathan-crypto: call init({ ${mod}: ... }) before using this class"` |
| Invalid `WasmSource` (null, number, etc.)     | Throws: `TypeError` with a descriptive message                                   |
| Empty string source                           | Throws: `"leviathan-crypto: invalid WasmSource -- empty string"`                 |
| Calling `init()` for an already-loaded module | No error. Module is silently skipped (idempotent behavior)                       |

---

> ## Cross-References
>
> - [index](./README.md) -- Project Documentation index
> - [loader](./loader.md) -- WASM binary loading strategies (internal details)
> - [architecture](./architecture.md) -- architecture overview, module relationships, buffer layouts, and build pipeline
> - [wasm](./wasm.md) -- WebAssembly primer: modules, instances, memory, and the init gate
