# WASM Binary Loading Strategies

> [!NOTE]
> Internal module used by `init()` that handles the actual loading and
> instantiation of WebAssembly binaries. You normally do not interact
> with this module directly.

> ### Table of Contents
> - [Overview](#overview)
> - [Security Notes](#security-notes)
> - [API Reference](#api-reference)
> - [Internal Details](#internal-details)

---

## Overview

When you call [`init()`](./init.md), it delegates the work of obtaining and compiling the
WASM binary to the loader. The loading strategy is inferred from the
`WasmSource` type, so no mode string is required:

**Embedded string.** gzip-compressed, base64-encoded WASM bundled in the package. Decoded and decompressed at [`init()`](./init.md) time using `DecompressionStream`. No network requests. This is the default and simplest option.

**URL.** Fetches the `.wasm` file and uses the browser's streaming compilation API. The browser can start compiling while still downloading.

**ArrayBuffer / Uint8Array.** Raw WASM bytes, compiled directly.

**WebAssembly.Module.** Already compiled. Instantiated immediately. Useful for edge runtimes and KV-cached modules.

**Response / Promise\<Response\>.** Streaming compilation from an in-flight or deferred fetch.

All strategies produce the same result: a `WebAssembly.Instance` that the
wrapper classes use to perform cryptographic operations.

---

## Security Notes

**Embedded mode requires no network access.** The WASM binary is part of the installed package. This eliminates the risk of a compromised CDN or man-in-the-middle attack altering the binary at load time.

**URL-based loading requires correct MIME type.** The `.wasm` files must be served with `Content-Type: application/wasm`. This is a browser requirement for `WebAssembly.instantiateStreaming`. If the header is missing or wrong, the browser will reject the response.

**Raw binary / Module sources place integrity responsibility on you.** The loader instantiates whatever binary you provide. If you supply your own bytes or pre-compiled Module, you are responsible for verifying authenticity.

**Each module gets its own memory.** Every instantiation creates a fresh `WebAssembly.Memory` with 3 pages (192 KB). Modules cannot share or access each other's memory. Key material in one module's memory space is isolated from all other modules.

---

## API Reference

These functions are exported from `loader.ts` and called by `init.ts`. They
are not part of the public API. They are documented here for completeness and for contributors working on the internals.

### `loadWasm(source)`
```typescript
async function loadWasm(source: WasmSource): Promise<WebAssembly.Instance>
```

Loads and instantiates a WASM module from any accepted source type. Each
instance receives a fresh 3-page `WebAssembly.Memory`.

**Source type handling:**

| Source type                    | Loading path                                                         |
|--------------------------------|----------------------------------------------------------------------|
| `string`                       | Decoded from gzip+base64 via `decodeWasm()`, then `WebAssembly.instantiate()`. |
| `URL`                          | `WebAssembly.instantiateStreaming(fetch(url))`.                      |
| `ArrayBuffer`                  | `WebAssembly.instantiate()`.                                         |
| `Uint8Array`                   | `WebAssembly.instantiate()`.                                         |
| `WebAssembly.Module`           | `WebAssembly.instantiate(module, imports)`.                          |
| `Response` / `Promise<Response>` | `WebAssembly.instantiateStreaming()`.                              |

**Throws:**

- `TypeError` if `source` is null, numeric, or otherwise unrecognised.
- `TypeError` with `"empty string"` if `source` is an empty string.

**Runtime guards:** `Response` and `Promise` checks are guarded with
`typeof Response !== 'undefined'` to avoid `ReferenceError` in runtimes
where these globals do not exist (Node < 18).

---

### `compileWasm(source)`
```typescript
async function compileWasm(source: WasmSource): Promise<WebAssembly.Module>
```

Compiles a `WasmSource` to a `WebAssembly.Module` without instantiating it.
Used by pool infrastructure to send a compiled module to workers. Each worker receives the `Module` and instantiates it with their own isolated memory.

**Source type handling:** Same dispatch table as `loadWasm()`, but calls
`WebAssembly.compile()` / `WebAssembly.compileStreaming()` instead of the
`instantiate` variants. `WebAssembly.Module` sources are returned as-is.

**Throws:** Same as `loadWasm()`.

---

### `decodeWasm(b64)`
```typescript
async function decodeWasm(b64: string): Promise<Uint8Array>
```

Decodes a gzip-compressed, base64-encoded WASM string to raw bytes.

1. Base64-decodes the string using the shared `base64ToBytes` utility.
2. Decompresses the result using `DecompressionStream('gzip')`.

**Throws:**

- `Error` if `DecompressionStream` is not available in the runtime.
  The error message directs the user to provide a URL, ArrayBuffer, or
  WebAssembly.Module source instead.
- `Error` if base64 decoding fails (corrupt embedded blob).

Exported for use by pool worker launchers that need to decode blobs
before spawning threads.

---

## Internal Details

### Embedded binary structure

Each module provides two paths to its embedded blob:

| Path                                   | Export          | Used by                     |
|----------------------------------------|-----------------|-----------------------------|
| `src/ts/embedded/serpent.ts`           | (raw blob)      | Build artifact, gitignored  |
| `src/ts/serpent/embedded.ts`           | `serpentWasm`   | Consumer import             |

The per-module `embedded.ts` re-exports the generated blob as a named
export. Consumers import from the `/embedded` subpath:
```typescript
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'
```

The `src/ts/embedded/` directory is generated by `scripts/embed-wasm.ts`
and is gitignored. These files are not meant to be created or edited by hand.

### Embedded compression

The embedded files contain gzip-compressed WASM encoded as base64.
Compression reduces the embedded footprint from ~198 KB to ~33 KB across
all four modules, with Serpent alone shrinking from ~167 KB to ~20 KB.

### Memory allocation

Every WASM instance receives a `WebAssembly.Memory` with exactly 3 pages
(192 KB total). The memory size is fixed; modules do not grow their memory at runtime. This is a deliberate design choice: fixed memory prevents
unexpected allocations and makes the memory layout predictable and auditable.

---

> ## Cross-References
>
> - [index](./README.md) — Project Documentation index
> - [architecture](./architecture.md) — architecture overview, module relationships, buffer layouts, and build pipeline
> - [init](./init.md) — the public `init()` API that uses this loader
> - [wasm](./wasm.md) — WebAssembly primer: modules, instances, and memory model
