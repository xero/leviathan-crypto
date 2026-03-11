# XChaCha20Poly1305Pool: Parallel Worker Pool for Authenticated Encryption

> [!NOTE]
> A worker pool that dispatches independent XChaCha20-Poly1305 AEAD operations
> across multiple Web Workers, each with its own isolated WebAssembly instance.

## Overview

`XChaCha20Poly1305Pool` parallelizes XChaCha20-Poly1305 encrypt and decrypt
operations across Web Workers. Each worker owns its own `WebAssembly.Instance`
with its own linear memory -- there is no shared state between workers.

Use the pool when you need to process many independent AEAD operations
concurrently. Typical use cases include encrypting multiple independent messages,
batch processing encrypted records, or any scenario where multiple independent
encrypt/decrypt operations could benefit from parallelism.

Use the single-instance `XChaCha20Poly1305` when operations are sequential, when
you only process one message at a time, or when the overhead of worker
communication is not justified by the operation size.

**Throughput ceiling:** CPU-bound WASM throughput plateaus at
`navigator.hardwareConcurrency`. Adding more workers beyond this adds scheduling
overhead with no parallelism gain.

**Per-job size limit:** Each job is limited to 64 KB, the same limit as the
single-instance path. This is not a workaround limitation -- it is the correct
security boundary for independent AEAD operations. Each job is one complete,
independently authenticated AEAD operation. Do not split one logical message
across multiple pool calls and concatenate results -- this provides no
stream-level authenticity (reordering and truncation attacks go undetected).

---

## Security Notes

- **Input buffers are transferred (neutered) after dispatch.** Once you call
  `encrypt()` or `decrypt()`, the `key`, `nonce`, `plaintext`/`ciphertext`, and
  `aad` buffers are transferred to the worker via `Transferable`. The caller's
  `Uint8Array` views become detached -- reading them after the call returns
  zero-length buffers. If you need to retain any input after calling
  `encrypt()`/`decrypt()`, copy it first with `.slice()`.

- **64 KB limit is per independent AEAD operation.** Do not split one logical
  message across multiple pool calls and concatenate the results. This creates a
  stream without authentication -- an attacker can reorder, duplicate, or
  truncate chunks without detection. A future chunked-AEAD streaming API is the
  correct tool for large files.

- **All XChaCha20-Poly1305 security properties apply.** Nonce uniqueness per key
  is required. The 24-byte nonce is safe for random generation via
  `crypto.getRandomValues()` (collision probability is negligible for 2^64
  messages).

- **Each worker owns isolated WASM memory.** Key material in one worker's linear
  memory cannot leak to another worker, even in theory.

- **Workers are terminated on `dispose()`.** All WASM memory is released when
  the worker process ends. There is no lingering key material.

---

## API Reference

### `PoolOpts`

```typescript
interface PoolOpts {
  /** Number of workers. Default: navigator.hardwareConcurrency ?? 4 */
  workers?: number;
}
```

---

### `XChaCha20Poly1305Pool.create(opts?)`

Static async factory. Returns a `Promise<XChaCha20Poly1305Pool>`.

```typescript
static async create(opts?: PoolOpts): Promise<XChaCha20Poly1305Pool>
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `opts.workers` | `number` | `navigator.hardwareConcurrency ?? 4` | Number of workers to spawn. |

Throws if `init(['chacha20'])` has not been called.

Direct construction with `new XChaCha20Poly1305Pool()` is not possible -- the
constructor is private.

---

### `encrypt(key, nonce, plaintext, aad?)`

Encrypt plaintext with XChaCha20-Poly1305.

```typescript
encrypt(
  key: Uint8Array,       // 32 bytes
  nonce: Uint8Array,     // 24 bytes
  plaintext: Uint8Array, // up to 64 KB
  aad?: Uint8Array,      // optional additional authenticated data
): Promise<Uint8Array>   // ciphertext || tag (plaintext.length + 16 bytes)
```

| Parameter | Type | Constraints | Description |
|-----------|------|-------------|-------------|
| `key` | `Uint8Array` | 32 bytes | Encryption key |
| `nonce` | `Uint8Array` | 24 bytes | Unique nonce |
| `plaintext` | `Uint8Array` | 0--65536 bytes | Data to encrypt |
| `aad` | `Uint8Array` | any length | Additional authenticated data (default: empty) |

Returns `ciphertext || tag` (`plaintext.length + 16` bytes).

> [!WARNING]
> All input buffers are transferred and neutered after dispatch.

### `decrypt(key, nonce, ciphertext, aad?)`

Decrypt ciphertext with XChaCha20-Poly1305.

```typescript
decrypt(
  key: Uint8Array,        // 32 bytes
  nonce: Uint8Array,      // 24 bytes
  ciphertext: Uint8Array, // ciphertext || tag (at least 16 bytes)
  aad?: Uint8Array,       // must match the AAD used during encryption
): Promise<Uint8Array>    // plaintext
```

| Parameter | Type | Constraints | Description |
|-----------|------|-------------|-------------|
| `key` | `Uint8Array` | 32 bytes | Decryption key |
| `nonce` | `Uint8Array` | 24 bytes | Same nonce used for encryption |
| `ciphertext` | `Uint8Array` | >= 16 bytes | `ciphertext || tag` from `encrypt()` |
| `aad` | `Uint8Array` | any length | Same AAD used during encryption (default: empty) |

Returns the decrypted plaintext.

Rejects with `Error('ChaCha20Poly1305: authentication failed')` if the tag does
not match (tampered ciphertext, wrong key, wrong nonce, or wrong AAD).

> [!WARNING]
> All input buffers are transferred and neutered after dispatch.

### `dispose()`

Terminate all workers and reject all pending and queued jobs.

```typescript
dispose(): void
```

After `dispose()`, all calls to `encrypt()` and `decrypt()` reject immediately.
Calling `dispose()` multiple times is safe (idempotent).

---

### `size`

Number of workers in the pool.

```typescript
get size(): number
```

---

### `queueDepth`

Number of jobs currently queued (waiting for a free worker).

```typescript
get queueDepth(): number
```

Returns 0 when all workers are idle.

---

## Performance Notes

Throughput plateaus at `navigator.hardwareConcurrency` workers for CPU-bound
WASM operations. Adding more workers beyond this count introduces scheduling
overhead without additional parallelism.

The `workers` option lets you tune the count:
- **Default** (`navigator.hardwareConcurrency ?? 4`) -- optimal for most systems
- **Fewer workers** -- useful if you need to leave cores available for other work
- **More workers** -- only beneficial on hyperthreaded CPUs where
  `hardwareConcurrency` includes virtual cores that provide some additional
  throughput

Each worker carries a fixed overhead: one `WebAssembly.Instance` (192 KB linear
memory) plus the worker thread itself. For most workloads, the default is correct.

Job dispatch uses `Transferable` buffers to avoid copy overhead on 64 KB payloads.
The downside is that input buffers are neutered on the calling side -- see
Security Notes.

---

## Usage Examples

### Basic -- create pool, encrypt/decrypt one message

```typescript
import { init, XChaCha20Poly1305Pool, randomBytes } from 'leviathan-crypto'

await init(['chacha20'])

const pool = await XChaCha20Poly1305Pool.create()

const key   = randomBytes(32)
const nonce = randomBytes(24)
const plaintext = new TextEncoder().encode('Hello, world!')

// Copy inputs before passing to the pool (they will be neutered)
const ct = await pool.encrypt(key.slice(), nonce.slice(), plaintext.slice())
const pt = await pool.decrypt(key.slice(), nonce.slice(), ct)
console.log(new TextDecoder().decode(pt))  // "Hello, world!"

pool.dispose()
```

### Concurrent burst -- `Promise.all()` over many independent messages

```typescript
import { init, XChaCha20Poly1305Pool, randomBytes } from 'leviathan-crypto'

await init(['chacha20'])
const pool = await XChaCha20Poly1305Pool.create()

const messages = ['message-1', 'message-2', 'message-3', 'message-4']
const key = randomBytes(32)

// Each message gets its own nonce -- all encrypt concurrently
const encrypted = await Promise.all(
  messages.map(msg => {
    const nonce = randomBytes(24)
    const pt = new TextEncoder().encode(msg)
    return pool.encrypt(key.slice(), nonce, pt)
  })
)

pool.dispose()
```

### Manual worker count

```typescript
const pool = await XChaCha20Poly1305Pool.create({ workers: 4 })
console.log(pool.size)  // 4
```

### Correct dispose pattern -- `try/finally`

```typescript
const pool = await XChaCha20Poly1305Pool.create()
try {
  const ct = await pool.encrypt(key, nonce, plaintext)
  // ... use ct ...
} finally {
  pool.dispose()
}
```

### What NOT to do -- splitting one message across pool calls

```typescript
// WRONG -- this is NOT secure
const chunk1 = await pool.encrypt(key, nonce1, largeFile.subarray(0, 65536))
const chunk2 = await pool.encrypt(key, nonce2, largeFile.subarray(65536))
const result = concat(chunk1, chunk2)
// ^ An attacker can reorder, duplicate, or truncate chunks undetected.
//   There is no stream-level authentication.
//   Use a future chunked-AEAD streaming API for large files.
```

---

## Error Conditions

| Condition | What happens |
|-----------|-------------|
| `init()` not called | `create()` throws: `leviathan-crypto: call init(['chacha20']) before using XChaCha20Poly1305Pool` |
| `new XChaCha20Poly1305Pool()` | Compile-time error -- the constructor is private |
| Wrong key length | `encrypt()`/`decrypt()` reject with `RangeError` |
| Wrong nonce length | `encrypt()`/`decrypt()` reject with `RangeError` |
| Ciphertext shorter than 16 bytes | `decrypt()` rejects with `RangeError` |
| Authentication failure | `decrypt()` rejects with `Error('ChaCha20Poly1305: authentication failed')` |
| Pool disposed | `encrypt()`/`decrypt()` reject with `Error('leviathan-crypto: pool is disposed')` |
| Worker init failure | `create()` rejects with error message from the worker |

---

## Cross-References

- [chacha20.md](./chacha20.md): Single-instance XChaCha20-Poly1305 API
- [fortuna.md](./fortuna.md): Another class using the `static async create()` factory pattern
- [architecture.md](./architecture.md): Library architecture and module relationships
- [README.md](./README.md): Project overview and getting started
