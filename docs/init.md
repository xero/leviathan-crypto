# Module Initialization and WASM Loading

> [!NOTE]
> The `init()` function is the entry point for leviathan-crypto. You must call it
> before using any cryptographic class. It loads the WebAssembly modules that
> perform the actual cryptographic work, caches them in memory, and makes them
> available to all wrapper classes.

## Overview

leviathan-crypto runs all cryptographic computation inside WebAssembly modules.
These modules are not available automatically, they need to be loaded and
compiled before any cryptographic class (`Serpent`, `SHA256`, `ChaCha20`, etc.)
can be used.

`init()` handles this process for you. You tell it which modules you need, and
it loads them. After that, every class backed by those modules is ready to use.

Key properties:

- **Required before use.** If you try to create a cryptographic class before
  calling `init()`, you will get a clear error telling you what to do.
- **Three loading modes.** Embedded (default, zero-config), streaming
  (better performance for large apps), and manual (full control over how
  binaries are provided).
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

| Module      | Classes it enables                                              |
|-------------|----------------------------------------------------------------|
| `'serpent'` | `Serpent`, `SerpentCbc`, `SerpentCtr`, `SerpentGcm`, `Fortuna` |
| `'chacha20'`| `ChaCha20`, `XChaCha20Poly1305`                                |
| `'sha2'`    | `SHA256`, `SHA384`, `SHA512`, `HMAC` (SHA-2 based), `Fortuna`  |
| `'sha3'`    | `SHA3`, `SHAKE128`, `SHAKE256`                                 |
| `'argon2id'`| `Argon2id` — **not part of the `Module` union.** Uses its own init type (`'embedded' \| 'manual'`), not the root `Module` type. See [README.md](./README.md) for its dedicated init path. |

```typescript
type Mode = 'embedded' | 'streaming' | 'manual'
```

How the WASM binary is loaded. See the [Usage Examples](#usage-examples) section
for when to use each mode.

```typescript
interface InitOpts {
  wasmUrl?: URL | string
  wasmBinary?: Partial<Record<Module, Uint8Array | ArrayBuffer>>
}
```

Optional configuration object. Which fields are required depends on the mode:

| Mode        | Required fields    | Description                                     |
|-------------|--------------------|-------------------------------------------------|
| `embedded`  | (none)             | Binaries are bundled in the package              |
| `streaming` | `wasmUrl`          | Base URL where `.wasm` files are served          |
| `manual`    | `wasmBinary`       | A map of module names to raw WASM binary data    |

---

### Functions

#### `init(modules, mode?, opts?)` — public API (exported from root barrel)

> [!NOTE]
> `init()` is no longer exported from `init.ts`. It is defined in the
> root barrel (`src/ts/index.ts`) and dispatches to each module's own `init()`.
> See [README.md](./README.md) for details.

The public `init()` signature is unchanged:

```typescript
async function init(
  modules: Module | Module[],
  mode?: Mode,        // default: 'embedded'
  opts?: InitOpts,
): Promise<void>
```

---

#### `initModule(mod, embeddedThunk, mode?, opts?)` — internal

```typescript
async function initModule(
  mod: Module,
  embeddedThunk: () => Promise<string>,
  mode?: Mode,        // default: 'embedded'
  opts?: InitOpts,
): Promise<void>
```

Internal initialization function. Called by each module's own `init()`,
not by consumers directly. Each module passes its own embedded thunk so the
dependency graph stays isolated per module, enabling tree-shaking.

**Parameters:**

- `mod`: The module name to initialize.
- `embeddedThunk`: A function that returns a Promise resolving to the
  base64-encoded WASM binary. Each module defines its own thunk pointing to
  its own embedded file.
- `mode`: The loading strategy. Defaults to `'embedded'`.
- `opts`: Configuration for `'streaming'` and `'manual'` modes.

**Returns:** A Promise that resolves when the module is loaded and cached.

**Idempotent:** If the module is already initialized, returns immediately.

**Throws:**

- `'leviathan-crypto: streaming mode requires wasmUrl'` if mode is
  `'streaming'` and `opts.wasmUrl` is not provided.
- `'leviathan-crypto: manual mode requires wasmBinary['<mod>']'` if mode
  is `'manual'` and the binary for the requested module is missing.
- `'leviathan-crypto: unknown mode '<mode>''` if an invalid mode string
  is passed.

> [!NOTE]
> The previous design exported `init()` from `init.ts`,
> which contained a central `embeddedLoaders` record mapping every module name
> to its embedded import. This meant any consumer importing `init()`,
> even through a subpath like `leviathan-crypto/serpent`, pulled all four
> embedded binaries into the bundle. Moving `init()` to the root barrel and
> giving each module its own thunk isolates the dependency graph so bundlers
> can tree-shake unused modules, optimizing build size.

#### `getInstance(mod)`

```typescript
function getInstance(mod: Module): WebAssembly.Instance
```

Returns the cached WebAssembly instance for a module. This is used internally
by wrapper classes, you do not normally need to call it yourself.

**Throws:**
`'leviathan-crypto: call init(['<mod>']) before using this class'` if the
module has not been initialized.

---

#### `isInitialized(mod)`

```typescript
function isInitialized(mod: Module): boolean
```

Returns `true` if the given module has been loaded and cached. Useful for
conditional logic where you want to check readiness without catching an error.

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

### Embedded mode (default: simplest)

This is the recommended mode for most applications. The WASM binaries are
bundled inside the package as base64-encoded strings, so there are no extra
files to serve or fetch.

```typescript
import { init, SHA256 } from 'leviathan-crypto'

await init('sha2')

const hash = new SHA256()
const digest = hash.hash(myData)
```

### Initializing multiple modules at once

Pass an array to load several modules in a single call:

```typescript
import { init, Serpent, SHA256 } from 'leviathan-crypto'

await init(['serpent', 'sha2'])

const cipher = new Serpent(key)
const hash = new SHA256()
```

### Streaming mode (better performance for large apps)

Streaming mode fetches `.wasm` files from a URL and uses the browser's
streaming compilation (`WebAssembly.instantiateStreaming`). This can be
faster than embedded mode because the browser can begin compiling the WASM
binary while it is still downloading.

You must serve the `.wasm` files from your web server and provide the base
URL where they are hosted. The files must be served with the
`Content-Type: application/wasm` header.

```typescript
import { init, Serpent } from 'leviathan-crypto'

await init('serpent', 'streaming', {
  wasmUrl: '/static/wasm/'
})

const cipher = new Serpent(key)
```

The library knows the filename for each module (e.g. `serpent.wasm`,
`sha2.wasm`). You only need to provide the directory URL.

### Manual mode (full control)

Manual mode lets you provide the raw WASM binary yourself. This is useful if
you have a custom build pipeline, want to load binaries from a non-standard
source, or need to verify the binary before passing it to the library.

```typescript
import { init, SHA256 } from 'leviathan-crypto'

// Load the binary however you like
const wasmBinary = await fetch('/my-custom-path/sha2.wasm')
  .then(r => r.arrayBuffer())

await init('sha2', 'manual', {
  wasmBinary: { sha2: new Uint8Array(wasmBinary) }
})

const hash = new SHA256()
```

### Checking if a module is initialized

```typescript
import { isInitialized } from 'leviathan-crypto'

if (!isInitialized('sha2')) {
  await init('sha2')
}
```

---

## Error Conditions

| Situation                                 | What happens                                                                                 |
|-------------------------------------------|----------------------------------------------------------------------------------------------|
| Using a class before calling `init()`     | Throws: `"leviathan-crypto: call init(['<mod>']) before using this class"`                    |
| Streaming mode without `wasmUrl`          | Throws: `"leviathan-crypto: streaming mode requires wasmUrl"`                                |
| Manual mode without the needed binary     | Throws: `"leviathan-crypto: manual mode requires wasmBinary['<mod>']"`                       |
| Unknown mode string                       | Throws: `"leviathan-crypto: unknown mode '<mode>'"`                                          |
| Streaming mode requested for argon2id         | Throws: `"leviathan-crypto: argon2id does not support streaming mode"`               |
| Calling `init()` for an already-loaded module | No error. Module is silently skipped (idempotent behavior)                          |

---

## Cross-References

- [README.md](./README.md): Package overview and quick-start guide
- [loader.md](./loader.md): WASM binary loading strategies (internal details)
- [architecture.md](./architecture.md): Architecture overview
