# WebAssembly Primer

> [!NOTE]
> - A short introduction to WebAssembly concepts as they apply to the leviathan-crypto library.
> - If you already understand WASM, skip to [Project-Specific Concepts](#project-specific-concepts).
> - WebAssembly specification and documentation: [webassembly.org](https://webassembly.org/)

## What is WebAssembly?

WebAssembly (WASM) is a binary instruction format that runs in browsers and
server-side runtimes alongside JavaScript. Rather than a programming language
one writes by hand, it serves as a compilation target. Code is written in a higher-level
language, compiled to `.wasm`, and then executed by the browser.

Consider it a small, fast virtual machine built into every modern browser.
JavaScript can load a `.wasm` binary, call its exported functions, and read
its results. The WASM code runs in its own sandboxed memory space, and thus cannot
touch the DOM, access JavaScript variables, or reach the network. It computes
and returns values, and that is its sole function.

---

## How It Runs

When a browser encounters a `.wasm` binary, it performs two steps:

1. Compilation: The binary is validated and compiled into native machine code.
   This is fast because WASM is already a low-level format, requiring less
   work for the compiler compared to parsing and optimizing JavaScript.

2. Instantiation: The compiled module is paired with its imports, such as a
   memory object, to create a live instance. The instance's exported functions
   are then callable from JavaScript.

Once instantiated, calling a WASM function is similar to calling any JavaScript
function: you pass arguments, it runs, and it returns a result. The key difference
lies in how it runs. WASM execution is deterministic and not subject to the
JIT compiler's speculative optimizations. Unlike JavaScript, the browser does not rewrite, inline,
or de-optimize WASM code paths based on runtime profiling.

---

## Why We Use It

Leviathan performs all cryptographic computations in WASM because JavaScript
engines offer no formal constant-time guarantees for arbitrary code. The JIT
compiler can introduce timing variations that leak information about secret
data; WASM execution avoids this class of problem.

For architectural details and security rationale, see [architecture.md](./architecture.md).

**TLDR:** _TypeScript handles the API, and WASM handles the math._

---

## Core Concepts

### Module

A `WebAssembly.Module` is a compiled `.wasm` binary and a stateless
template for creating instances. You can compile a module once and create
multiple instances from it. For example, [XChaCha20Poly1305Pool](./chacha20_pool.md)
uses one compiled module to create many worker instances.

---

### Instance

A WebAssembly.Instance is a live, runnable copy of a module, complete with
its own memory and state. When you call `init('serpent')`, the library
compiles the Serpent WASM binary and creates a single instance. All
Serpent classes (`Serpent`, `SerpentCtr`, `SerpentCbc`) share this instance.

---

### Memory

A `WebAssembly.Memory` is a contiguous block of bytes, essentially a
 `Uint8Array` that WASM functions can read and write, also known as **linear
memory**. Each of our WASM modules gets its own memory (3 pages = 192 KB).

The TypeScript layer communicates with WASM by writing inputs to specific offsets
in this memory, calling a WASM function, and then reading the outputs from other
offsets. There is no other communication channel, no function arguments for
large data, and no return values beyond a single number. Memory is the data bus.

---

### Exports

A WASM instance exposes exports: functions and memory that JavaScript can
access. In leviathan-crypto, every WASM module exports:

- **Getter functions** like getKeyOffset() and getChunkPtOffset(): these
  return the memory offsets where the TypeScript layer should write inputs
  or read outputs.
- **Operation functions** like chachaEncryptChunk() and sha256Final():
  these perform the actual cryptographic computation on data already in memory.
- **wipeBuffers():** this zeros all sensitive regions of memory and is called
  by every class's dispose() method.
- **memory:** the linear memory object itself, which allows the TypeScript
  layer to create Uint8Array views over it.

---

### Imports

When instantiating a module, you can pass **imports:** objects the WASM code
needs from the host. Our modules import only one thing: the Memory object.
We create the memory on the JavaScript side and pass it in, giving us
control over its size and lifecycle.

---

## Project-Specific Concepts

### AssemblyScript

The WASM binaries in this project are written in [AssemblyScript](https://www.assemblyscript.org/):
a TypeScript-like language that compiles to WebAssembly. It resembles
TypeScript but targets WASM instead of JavaScript. The source code
resides in `src/asm/` and compiles into `.wasm` binaries in `build/`.

AssemblyScript was selected because its syntax is familiar to TypeScript
developers. It produces small binaries and grants low-level control over
memory layout without requiring C, C++, or Rust.

---

### Thunks

In this project, a **thunk** is a base64-encoded WASM binary embedded directly
within a TypeScript file. The files in `src/ts/embedded/`
(such as chacha20.ts and serpent.ts) each export a single constant:

```typescript
export const WASM_BASE64 = 'AGFzbQEAAAAB...'
```

This represents the entire compiled .wasm binary, encoded as a base64 string. When
you call init('chacha20') in embedded mode (the default), the library
imports this string, decodes it back into bytes, and compiles it into a
`WebAssembly.Module`.

Why embed the binary as a string? This approach enables the library to function with zero
configuration. There's no need to serve .wasm files from a CDN, configure MIME
types, or establish a build plugin to manage binary imports. Simply npm install and
import. The tradeoff is bundle size, as base64 encoding increases the size by
approximately 33% compared to the raw binary. For production deployments where bundle size is
critical, the library also supports [streaming and manual loading modes](./loader.md).

**TLDR:** Thunks are build artifacts generated by `scripts/embed-wasm.ts`.
They are gitignored and regenerated during each build. Avoid manual edits.

---

### Buffer Layout

Each WASM module divides its linear memory into fixed regions at known offsets.
For example, the ChaCha20 module has a region for the key, a region for the
nonce, a region for plaintext input, a region for ciphertext output, and so on.
These offsets are defined in `src/asm/*/buffers.ts` and never change at runtime.
The TypeScript layer calls getter functions (like `getKeyOffset()`) to
determine where each region starts, then reads and writes `Uint8Array` slices at those
positions. This is the only way data moves between TypeScript and
WASM. There is no serialization, no copying to intermediate buffers, and no function call
overhead for large data. Data is transferred via direct byte writes to shared memory.

The buffer layouts for each module are documented in [architecture.md](./architecture.md).

---

### The `init()` Gate

WASM modules must be compiled and instantiated before use. Because compilation
returns a Promise, this is an asynchronous operation. Rather than hiding this
behind lazy auto-initialization, which would make every cryptographic call
implicitly asynchronous and create race conditions, the library requires an explicit
`init()` call up front. If you forget, every class immediately throws an error message
indicating which `init(init()` call is missing. _This is deliberate._

See [init.md](./init.md) for the full API.

---

> ## Cross-References
>
> - [index](./README.md) — Project Documentation index
> - [architecture](./architecture.md) — architecture overview, module relationships, buffer layouts, and build pipeline
> - [serpent_simd_bench](./serpent_simd_bench.md) Serpent-256 SIMD benchmark results: CTR and CBC-decrypt inter-block 4-wide, scalar vs SIMD across V8, SpiderMonkey, and JSC
> - [chacha_simd_bench](./chacha_simd_bench.md) ChaCha20 SIMD benchmark results: 4-wide inter-block parallelism, scalar vs SIMD across V8, SpiderMonkey, and JSC. Includes documented negative result for intra-block approach
> - [init](./init.md) — `init()` API and the three loading modes
> - [loader](./loader.md) — how WASM binaries are loaded and instantiated
> - [chacha20_pool](./chacha20_pool.md) — example of one compiled module spawning many instances across workers
