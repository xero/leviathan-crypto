# WASM Binary Loading Strategies

> [!NOTE]
> Internal module used by `init()` that handles the actual loading and
> instantiation of WebAssembly binaries. You normally do not interact
> with this module directly.

## Overview

When you call `init()`, it delegates the work of obtaining and compiling the
WASM binary to the loader. The loader supports three strategies:

- **Embedded** -- The WASM binary is already bundled in the package as a
  base64-encoded string. The loader decodes it and instantiates the module.
  No network requests are made. This is the default and simplest option.
- **Streaming** -- The loader fetches the `.wasm` file from a URL you provide
  and uses the browser's streaming compilation API. The browser can start
  compiling the binary while it is still downloading, which can improve
  load times for larger modules.
- **Manual** -- You provide the raw binary data (as a `Uint8Array` or
  `ArrayBuffer`) and the loader instantiates it directly. This gives you
  full control over how the binary is obtained.

All three strategies produce the same result: a `WebAssembly.Instance` that
the wrapper classes use to perform cryptographic operations.

---

## Security Notes

- **Embedded mode requires no network access.** The WASM binary is part of
  the installed package. This eliminates the risk of a compromised CDN or
  man-in-the-middle attack altering the binary at load time.
- **Streaming mode requires correct MIME type.** The `.wasm` files must be
  served with `Content-Type: application/wasm`. This is a browser requirement
  for `WebAssembly.instantiateStreaming`. If the header is missing or wrong,
  the browser will reject the response.
- **Manual mode places integrity responsibility on you.** The loader
  instantiates whatever binary you provide. If you use manual mode, you are
  responsible for verifying that the binary is authentic and unmodified.
- **Each module gets its own memory.** Every instantiation creates a fresh
  `WebAssembly.Memory` with 3 pages (192 KB). Modules cannot share or
  access each other's memory. This means key material loaded into one
  module's memory space is isolated from all other modules.

---

## API Reference

These functions are exported from `loader.ts` and called by `init.ts`. They
are not part of the public API -- they are documented here for completeness
and for contributors working on the internals.

### `loadEmbedded(thunk)`

```typescript
async function loadEmbedded(
  thunk: () => Promise<string>,
): Promise<WebAssembly.Instance>
```

Loads a WASM module from an embedded base64-encoded string obtained by calling
the provided thunk.

**How it works:**

1. Calls the thunk, which dynamically imports the embedded binary file and
   returns the base64-encoded WASM string.
2. Decodes the base64 string to raw bytes.
3. Instantiates the WASM module with a fresh 3-page `WebAssembly.Memory`.

The thunk is provided by each module's own `init()` function (e.g.
`serpent/index.ts` passes `() => import('../embedded/serpent.js').then(m => m.WASM_BASE64)`).
This design means `loader.ts` has no knowledge of module names or embedded file
paths -- each module owns its own embedded import, enabling tree-shaking.

**Parameters:**

- `thunk` -- A function that returns a Promise resolving to a base64-encoded
  WASM binary string. Each module's `index.ts` defines its own thunk pointing
  to its own embedded file.

**Returns:** A Promise that resolves to a `WebAssembly.Instance`.

**Error conditions:**

- If the embedded binary file does not exist, this means the build step
  (`scripts/embed-wasm.ts`) has not been run. Run `npm run build` to
  generate the embedded files.

---

### `loadStreaming(mod, baseUrl, filename)`

```typescript
async function loadStreaming(
  _mod: Module,
  baseUrl: URL | string,
  filename: string,
): Promise<WebAssembly.Instance>
```

Loads a WASM module by fetching it from a URL and using streaming compilation.

**How it works:**

1. Constructs the full URL by combining `baseUrl` and `filename`
   (e.g. `https://example.com/wasm/` + `serpent.wasm`).
2. Calls `WebAssembly.instantiateStreaming(fetch(url), imports)`, which
   allows the browser to compile the module while it downloads.
3. Creates a fresh 3-page `WebAssembly.Memory` for the instance.

**Parameters:**

- `_mod` -- The module name (currently unused in the function body, but
  passed for consistency).
- `baseUrl` -- The base URL where `.wasm` files are hosted. Can be a
  `URL` object or a string.
- `filename` -- The `.wasm` filename (e.g. `'serpent.wasm'`). This is
  determined by `init.ts` using its internal filename mapping.

**Returns:** A Promise that resolves to a `WebAssembly.Instance`.

**Error conditions:**

- Network failure (server unreachable, 404, etc.) will cause the Promise
  to reject.
- If the server does not respond with `Content-Type: application/wasm`,
  the browser will reject the streaming compilation. This is a common
  issue with misconfigured web servers -- ensure your server is configured
  to serve `.wasm` files with the correct MIME type.

---

### `loadManual(binary)`

```typescript
async function loadManual(
  binary: Uint8Array | ArrayBuffer,
): Promise<WebAssembly.Instance>
```

Loads a WASM module from a raw binary you provide directly.

**How it works:**

1. Converts `ArrayBuffer` to `Uint8Array` if needed.
2. Instantiates the WASM module with a fresh 3-page `WebAssembly.Memory`.

**Parameters:**

- `binary` -- The raw WASM binary as a `Uint8Array` or `ArrayBuffer`.

**Returns:** A Promise that resolves to a `WebAssembly.Instance`.

**Error conditions:**

- If the binary is not a valid WASM module, `WebAssembly.instantiate` will
  throw. The error message will come from the browser's WASM engine and
  will typically mention a validation or compilation failure.

---

## Internal Details

### Embedded binary ownership

Each module's `index.ts` owns the dynamic import to its own embedded binary
file. The loader has no knowledge of module names or file paths -- it receives
a thunk from `initModule()` and calls it. This means `loader.ts` has no
dependency on any embedded file, which enables bundlers to tree-shake unused
modules.

| Module      | Thunk defined in              | Embedded file path         |
|-------------|-------------------------------|----------------------------|
| `serpent`   | `serpent/index.ts`            | `./embedded/serpent.js`    |
| `chacha20`  | `chacha20/index.ts`           | `./embedded/chacha.js`     |
| `sha2`      | `sha2/index.ts`               | `./embedded/sha2.js`       |
| `sha3`      | `sha3/index.ts`               | `./embedded/sha3.js`       |

The embedded `.js` files are generated by the build script
(`scripts/embed-wasm.ts`) and are gitignored. They are not meant to be
created or edited by hand.

### Base64 decoding

The loader handles base64 decoding in both browser and Node.js environments:

- **Browser:** Uses the built-in `atob()` function.
- **Node.js:** Falls back to `Buffer.from(b64, 'base64')`.

### Memory allocation

Every WASM instance receives a `WebAssembly.Memory` with exactly 3 pages
(192 KB total). The memory size is fixed -- modules do not grow their memory
at runtime. This is a deliberate design choice: fixed memory prevents
unexpected allocations and makes the memory layout predictable and auditable.

---

## Cross-References

- [README.md](./README.md)
- [architecture.md](./architecture.md): Architecture overview
- [init.md](./init.md): The public `init()` API that uses this loader
