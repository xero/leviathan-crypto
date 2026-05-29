<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### Content-Security-Policy

How to run leviathan-crypto under a strict Content-Security-Policy (CSP). The library compiles WebAssembly and, for the parallel pool, spawns Web Workers. Both are governed by CSP. This page lists exactly which directives the library requires, which it does not, and how the requirements differ across browser engines.

> ### Table of Contents
> - [Overview](#overview)
> - [Required directives](#required-directives)
> - [What the library does not need](#what-the-library-does-not-need)
> - [Minimal policies](#minimal-policies)
> - [Pool workers and worker-src](#pool-workers-and-worker-src)
> - [Strict CSP without blob:](#strict-csp-without-blob)
> - [Worked example](#worked-example)
> - [Cross-References](#cross-references)

---

## Overview

The library touches three CSP-relevant browser primitives, and nothing else.

**WebAssembly compilation.** Every module is compiled from bytes with `WebAssembly.compile` / `compileStreaming` and instantiated with `WebAssembly.instantiate`. Both steps require `'wasm-unsafe-eval'` in `script-src`. There is no `eval` and no `new Function` anywhere in the library, so `'unsafe-eval'` is never needed.

**Web Workers.** `SealStreamPool` spawns workers. The default cipher factories spawn a classic worker from a `blob:` URL, which requires `worker-src blob:` (and `child-src blob:` for engines that lack `worker-src`). You can override this to spawn a same-origin worker instead, which needs only `worker-src 'self'`.

**Network fetch.** Only the `URL` and `Response` [WasmSource](./loader.md) types fetch a `.wasm` file at load time, which requires `connect-src` for that origin. The embedded, `ArrayBuffer`, `Uint8Array`, and `WebAssembly.Module` sources make no network request.

Every claim on this page is backed by an end-to-end test that runs on Chromium, Firefox, and WebKit under a real CSP. See `test/e2e/loader_csp.spec.ts`, `test/e2e/loader_csp_negative.spec.ts`, and `test/e2e/pool_csp.spec.ts`.

---

## Required directives

| Directive | Required when | Why |
| --------- | ------------- | --- |
| `script-src 'wasm-unsafe-eval'` | Always | Compiling and instantiating any WASM module. May live on `default-src` instead. |
| `script-src 'self'` (or a hash/nonce for your bundle) | Always | Loading the library's own JavaScript modules. |
| `worker-src blob:` | `SealStreamPool` with the default factory | Spawning the pool worker from a `blob:` URL (Chromium and Firefox). |
| `child-src blob:` | `SealStreamPool` with the default factory | WebKit and older engines have no `worker-src` and fall back to `child-src`. |
| `worker-src 'self'` | `SealStreamPool` with the same-origin worker override | Spawning the pool worker from a served URL instead of a `blob:`. Required for WebKit under a strict CSP. |
| `connect-src <wasm-origin>` | `URL` or `Response` WasmSource only | Fetching the `.wasm` binary. Not needed for embedded or in-memory sources. |

> [!IMPORTANT]
> `'wasm-unsafe-eval'` is mandatory on every engine, not a copied-in habit. With the directive absent, the library cannot initialize. Chromium and Firefox reject the `compile` step; WebKit lets compilation through but rejects instantiation with "Refused to create a WebAssembly object". Either way `init()` throws. `'wasm-unsafe-eval'` grants WebAssembly compilation without granting `eval`, so it is strictly narrower than `'unsafe-eval'`. Use it.

---

## What the library does not need

The library never injects styles, loads images or fonts, uses `eval`, or reads from `data:` URLs. None of the following are required on its behalf.

- `'unsafe-eval'`. The library compiles WASM, it does not run `eval` or `new Function`.
- `'unsafe-inline'`. No inline scripts and no inline styles.
- `style-src`, `img-src`, `font-src`. No stylesheets, images, or fonts.

If your application needs any of these, that is your application's requirement, not the library's. The [worked example](#worked-example) below separates the two.

---

## Minimal policies

Pick the smallest policy that matches how you load the library. Each is shown as an HTTP response header; the [meta tag](#meta-tag-form) form follows.

**Embedded WASM, no pool.** The default and simplest setup. The gzip+base64 binary ships in the bundle, so there is no network fetch and no worker.

```
Content-Security-Policy: default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; object-src 'none'
```

**Embedded WASM with `SealStreamPool` (Chromium and Firefox).** Adds the `blob:` worker sources for the default pool factory.

```
Content-Security-Policy: default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src blob:; child-src blob:; object-src 'none'
```

**Embedded WASM with `SealStreamPool` (all engines, including WebKit).** Uses the same-origin worker override instead of a `blob:`. See [Strict CSP without blob:](#strict-csp-without-blob).

```
Content-Security-Policy: default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; object-src 'none'
```

**URL-loaded WASM, no pool.** Adds `connect-src` for the origin serving the `.wasm` files. Replace `'self'` with the binary's origin if it differs.

```
Content-Security-Policy: default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'; object-src 'none'
```

### Meta tag form

The same policy works as a `<meta>` tag for static hosting without header control.

```html
<meta http-equiv="Content-Security-Policy"
      content="default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; object-src 'none'">
```

> [!NOTE]
> A `<meta>` CSP ignores `frame-ancestors`, `sandbox`, and report directives. Those only work as an HTTP header. The script and worker directives the library needs are all honored in a meta tag.

---

## Pool workers and worker-src

`SealStreamPool` compiles its WASM modules on the main thread and posts the compiled `WebAssembly.Module` objects to its workers, so the main thread always needs `'wasm-unsafe-eval'` regardless of how the worker is spawned. The worker spawn itself is the part `worker-src` governs.

The default factory (`createPoolWorker` on `SerpentCipher`, `XChaCha20Cipher`, and the AES suite) spawns a classic worker from a `blob:` URL. The behavior under a restrictive CSP splits by engine, verified across all three in `test/e2e/pool_csp.spec.ts`.

- **Chromium and Firefox.** `worker-src blob:` admits the worker and the pool round-trips. The blob worker inherits the document CSP, so the `'wasm-unsafe-eval'` grant covers the worker's own instantiation step too.
- **WebKit and Safari.** The `blob:` worker resource is refused under a restrictive CSP even with `worker-src blob:` and `child-src blob:` present, though it works with no CSP at all. The pool cannot start. WebKit must use the same-origin worker override.

> [!CAUTION]
> If you ship `SealStreamPool` to Safari users under a CSP, the default `blob:` factory will fail there. Use the same-origin worker override below. It works on all three engines, so it is the portable choice for any pool deployment behind a strict CSP.

---

## Strict CSP without blob:

For environments that forbid `blob:` entirely, or that must support WebKit under CSP, override `createPoolWorker` to spawn a same-origin worker. The override is a plain spread over the cipher suite; do not change `formatEnum`, `hkdfInfo`, or any size field, or you break wire interop.

```typescript
import { XChaCha20Cipher } from 'leviathan-crypto'
import type { CipherSuite } from 'leviathan-crypto'

// Serve the shipped worker from your own origin, or bundle your own.
const CspXChaCha20Cipher: CipherSuite = {
  ...XChaCha20Cipher,
  createPoolWorker: () => new Worker(
    new URL('./xchacha20-pool-worker.js', import.meta.url),
    { type: 'module' },
  ),
}

const pool = await SealStreamPool.create(CspXChaCha20Cipher, key, { wasm, workers: 2 })
```

This needs `worker-src 'self'` and no `blob:`.

```
Content-Security-Policy: default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; object-src 'none'
```

> [!NOTE]
> A same-origin worker takes its CSP from its own HTTP response, not from the document. The main thread still needs `'wasm-unsafe-eval'` to compile the modules it posts to the worker. See [ciphersuite.md](./ciphersuite.md) for the full override pattern and the hybrid-suite case.

---

## Worked example

A real consumer application ships a policy in this shape. Most of it is the application's own surface; only two directives exist for the library. This version uses `worker-src 'self'` with the [same-origin worker override](#strict-csp-without-blob), so the pool works on Chromium, Firefox, and WebKit alike. The table separates the library directives from the application's.

```
default-src 'none';
script-src 'wasm-unsafe-eval' 'sha256-KS5USFs9rlShBDRR+9rICpSFOiWcg1vcLwvfjcbvwxk=';
style-src 'unsafe-inline';
connect-src 'self' wss: ws://localhost:* ws://127.0.0.1:*;
worker-src 'self';
img-src 'self' data: blob:;
font-src 'none';
base-uri 'none';
object-src 'none';
form-action 'none';
frame-ancestors 'none'
```

| Directive | Owner | Note |
| --------- | ----- | ---- |
| `script-src 'wasm-unsafe-eval'` | Library | WASM compilation. Mandatory. |
| `script-src 'sha256-...'` | Application | Hash of the app's own bundled script. The library loads inside that bundle, so no separate `'self'` is needed here. Apps that load the library as a separate module need `'self'` or its own hash. |
| `worker-src 'self'` | Library | `SealStreamPool` with the same-origin worker override. Works on all three engines, no `blob:` needed. |
| `style-src 'unsafe-inline'` | Application | The library injects no styles. |
| `connect-src 'self' wss: ws://...` | Application | WebSockets. The library needs `connect-src` only for `URL`/`Response` WasmSources. |
| `img-src 'self' data: blob:` | Application | The library loads no images. |
| `default-src`, `font-src`, `base-uri`, `object-src`, `form-action`, `frame-ancestors` | Application | General hardening, unrelated to the library. |

---


## Cross-References

| Document | Description |
| -------- | ----------- |
| [index](./README.md) | Project Documentation index |
| [init](./init.md) | the public `init()` API and `WasmSource` types |
| [loader](./loader.md) | WASM binary loading strategies and dispatch |
| [cdn](./cdn.md) | loading from a CDN with no bundler |
| [ciphersuite](./ciphersuite.md) | `CipherSuite` interface and the `createPoolWorker` override |
| [examples](./examples.md) | code examples for every primitive |
