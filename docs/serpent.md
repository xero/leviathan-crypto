# Serpent-256 block cipher TypeScript API

> [!NOTE]
> Authenticated encryption via `SerpentSeal`, plus low-level block, CTR, and CBC
> classes for advanced use.

## Overview

`SerpentSeal` is the primary encryption API for the Serpent module. It provides
authenticated Serpent-256 encryption in a single call -- no manual IV generation,
no separate MAC step, no room for misuse. Internally it uses Encrypt-then-MAC
(SerpentCbc + HMAC-SHA256) and verifies authentication before decryption.

For advanced use cases, three lower-level classes are available: `Serpent` (raw
16-byte block operations), `SerpentCtr` (counter mode streaming), and `SerpentCbc`
(cipher block chaining with PKCS7 padding). These are unauthenticated and require
explicit opt-in.

Serpent was an AES finalist. It uses 32 rounds versus AES's 10--14, yielding a
larger security margin at comparable speed in WASM.

---

## Security Notes

> [!IMPORTANT]
> Read this section carefully before using any Serpent class. These are not
> theoretical concerns. Ignoring them will render encryption useless.

### SerpentCbc and SerpentCtr are unauthenticated

This is the most dangerous mistake you can make with this module. An attacker who
can modify ciphertext encrypted with `SerpentCbc` or `SerpentCtr` will produce
corrupted plaintext on decryption -- and decryption will succeed without any
indication of tampering. There is no integrity check. The caller receives garbage
and has no way to distinguish it from the original message.

`SerpentSeal` eliminates this problem. It computes an HMAC tag over the ciphertext
and verifies it before decryption. If anything has been modified, `decrypt()` throws
instead of returning corrupted data.

Leviathan also offers a `XChaCha20Poly1305` implementation an alternative that
provides authenticated encryption with a different cipher. See
[chacha20.md](./chacha20.md).

### Never reuse a nonce or IV with the same key

- **CTR mode**: Reusing a nonce with the same key is catastrophic. It produces the
  same keystream, which means an attacker can XOR two ciphertexts together and
  recover both plaintexts. Always generate a fresh random nonce for each message.
- **CBC mode**: The IV (initialization vector) must be random and unpredictable for
  each encryption. A predictable IV enables chosen-plaintext attacks.

Use `randomBytes(16)` to generate nonces and IVs. `SerpentSeal` handles IV
generation internally.

### Always use 256-bit keys

Unless you have a specific reason to use a shorter key, pass a 32-byte key to
every Serpent operation. Shorter keys provide less security margin and there is no
meaningful performance benefit to using them. `SerpentSeal` requires a 64-byte key
(32 bytes encryption + 32 bytes MAC).

### Call dispose() when done

Every Serpent class holds key material in WebAssembly memory. When you are finished
with an instance, call `dispose()` to zero out all key material, intermediate
state, and buffers. Failing to call `dispose()` means sensitive data may persist
in memory longer than necessary.

---

## Module Init

Each module subpath exports its own init function for consumers who want
tree-shakeable imports.

### `serpentInit(mode?, opts?)`

Initializes only the serpent WASM binary. Equivalent to calling the
root `init(['serpent'], mode, opts)` but without pulling the other three
modules into the bundle.

**Signature:**

```typescript
async function serpentInit(mode?: Mode, opts?: InitOpts): Promise<void>
```

**Usage:**

```typescript
import { serpentInit, Serpent } from 'leviathan-crypto/serpent'

await serpentInit()
const cipher = new Serpent()
```

---

## API Reference

All classes require their WASM modules to be initialized before construction.
`SerpentSeal` requires both `serpent` and `sha2`. All other classes require
`serpent` only.

### SerpentSeal

Authenticated Serpent-256 encryption. Handles IV generation, HMAC computation,
and verification internally -- no manual IV or MAC management required.

```typescript
class SerpentSeal {
	constructor()
	encrypt(key: Uint8Array, plaintext: Uint8Array): Uint8Array
	decrypt(key: Uint8Array, data: Uint8Array): Uint8Array
	dispose(): void
}
```

#### `constructor()`

Creates a new SerpentSeal instance. Throws if `init(['serpent', 'sha2'])` has not
been called.

---

#### `encrypt(key: Uint8Array, plaintext: Uint8Array): Uint8Array`

Encrypts plaintext and returns a sealed blob containing the ciphertext and
authentication data. The output is opaque -- pass it directly to `decrypt()`.

- **key** -- exactly 64 bytes (32 bytes encryption key + 32 bytes MAC key).
  Throws `RangeError` if the length is not 64.
- **plaintext** -- any length.

A fresh random IV is generated internally for each call. Two encryptions of the
same plaintext with the same key produce different output.

---

#### `decrypt(key: Uint8Array, data: Uint8Array): Uint8Array`

Verifies the authentication tag and decrypts the sealed blob. MAC verification
happens before decryption -- if the data has been tampered with, `decrypt()` throws
and never returns corrupted plaintext.

- **key** -- exactly 64 bytes. Must be the same key used for encryption. Throws
  `RangeError` if the length is not 64.
- **data** -- the sealed blob from `encrypt()`. Must be at least 64 bytes. Throws
  `RangeError` if shorter. Throws `Error` if authentication fails.

---

#### `dispose(): void`

Wipes all key material and intermediate state from WASM memory. Delegates to both
internal SerpentCbc and HMAC_SHA256 instances.

---

### Serpent

Raw Serpent block encryption and decryption. Operates on exactly 16-byte blocks.
This class is a low-level building block, most users should use `SerpentSeal`
instead.

```typescript
class Serpent {
	constructor()
	loadKey(key: Uint8Array): void
	encryptBlock(plaintext: Uint8Array): Uint8Array
	decryptBlock(ciphertext: Uint8Array): Uint8Array
	dispose(): void
}
```

#### `constructor()`

Creates a new Serpent instance. Throws if `init(['serpent'])` has not been called.

---

#### `loadKey(key: Uint8Array): void`

Loads and expands a key for subsequent block operations. Must be called before
`encryptBlock()` or `decryptBlock()`.

- **key** -- 16, 24, or 32 bytes. Throws `RangeError` if the length is invalid.

---

#### `encryptBlock(plaintext: Uint8Array): Uint8Array`

Encrypts a single 16-byte block and returns the 16-byte ciphertext.

- **plaintext** -- exactly 16 bytes. Throws `RangeError` if the length is not 16.

---

#### `decryptBlock(ciphertext: Uint8Array): Uint8Array`

Decrypts a single 16-byte block and returns the 16-byte plaintext.

- **ciphertext** -- exactly 16 bytes. Throws `RangeError` if the length is not 16.

---

#### `dispose(): void`

Wipes all key material and intermediate state from WASM memory. Always call this
when you are done with the instance.

---

### SerpentCtr

Serpent in Counter (CTR) mode. Encrypts and decrypts data of any length as a
stream of chunks.

> [!WARNING]
> CTR mode is unauthenticated. An attacker can modify ciphertext
> without detection. Use `SerpentSeal` for authenticated encryption, or pair
> with HMAC-SHA256 (Encrypt-then-MAC).

```typescript
class SerpentCtr {
	constructor(opts: { dangerUnauthenticated: true })
	beginEncrypt(key: Uint8Array, nonce: Uint8Array): void
	encryptChunk(chunk: Uint8Array): Uint8Array
	beginDecrypt(key: Uint8Array, nonce: Uint8Array): void
	decryptChunk(chunk: Uint8Array): Uint8Array
	dispose(): void
}
```

#### `constructor(opts: { dangerUnauthenticated: true })`

Creates a new SerpentCtr instance. Throws if `init(['serpent'])` has not been
called. Throws if `{ dangerUnauthenticated: true }` is not passed:

```
leviathan-crypto: SerpentCtr is unauthenticated — use SerpentSeal instead.
To use SerpentCtr directly, pass { dangerUnauthenticated: true }.
```

---

#### `beginEncrypt(key: Uint8Array, nonce: Uint8Array): void`

Initializes the CTR state for encryption. Loads the key, sets the nonce, and
resets the internal counter to zero.

- **key** -- 16, 24, or 32 bytes. Throws `RangeError` if the length is invalid.
- **nonce** -- exactly 16 bytes. Throws `RangeError` if the length is not 16.

---

#### `encryptChunk(chunk: Uint8Array): Uint8Array`

Encrypts a chunk of plaintext and returns the same-length ciphertext. Call this
one or more times after `beginEncrypt()`. The internal counter advances
automatically.

- **chunk** -- any length up to the module's internal chunk buffer size. Throws
  `RangeError` if the chunk exceeds the maximum size.

---

#### `beginDecrypt(key: Uint8Array, nonce: Uint8Array): void`

Initializes the CTR state for decryption. Functionally identical to
`beginEncrypt()` -- CTR mode uses the same operation in both directions.

- **key** -- 16, 24, or 32 bytes. Throws `RangeError` if the length is invalid.
- **nonce** -- exactly 16 bytes. Throws `RangeError` if the length is not 16.

---

#### `decryptChunk(chunk: Uint8Array): Uint8Array`

Decrypts a chunk of ciphertext and returns the same-length plaintext.
Functionally identical to `encryptChunk()`.

- **chunk** -- any length up to the module's internal chunk buffer size. Throws
  `RangeError` if the chunk exceeds the maximum size.

---

#### `dispose(): void`

Wipes all key material and intermediate state from WASM memory.

---

### SerpentCbc

Serpent in Cipher Block Chaining (CBC) mode with automatic PKCS7 padding.
Encrypts and decrypts entire messages in a single call.

> [!WARNING]
> CBC mode is unauthenticated. Always authenticate the output with
> HMAC-SHA256 (Encrypt-then-MAC) or use `SerpentSeal` instead.

```typescript
class SerpentCbc {
	constructor(opts: { dangerUnauthenticated: true })
	encrypt(key: Uint8Array, iv: Uint8Array, plaintext: Uint8Array): Uint8Array
	decrypt(key: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array): Uint8Array
	dispose(): void
}
```

#### `constructor(opts: { dangerUnauthenticated: true })`

Creates a new SerpentCbc instance. Throws if `init(['serpent'])` has not been
called. Throws if `{ dangerUnauthenticated: true }` is not passed:

```
leviathan-crypto: SerpentCbc is unauthenticated — use SerpentSeal instead.
To use SerpentCbc directly, pass { dangerUnauthenticated: true }.
```

---

#### `encrypt(key: Uint8Array, iv: Uint8Array, plaintext: Uint8Array): Uint8Array`

Encrypts plaintext with Serpent CBC and PKCS7 padding. The returned ciphertext is
always a multiple of 16 bytes and is at least 16 bytes longer than the input (due
to padding).

- **key** -- 16, 24, or 32 bytes. Throws `RangeError` if the length is invalid.
- **iv** -- exactly 16 bytes. Must be random and unique for each (key, message)
  pair. Throws `RangeError` if the length is not 16.
- **plaintext** -- any length (including zero). PKCS7 padding is applied
  automatically.

Returns the ciphertext as a new `Uint8Array`.

---

#### `decrypt(key: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array): Uint8Array`

Decrypts Serpent CBC ciphertext and strips PKCS7 padding.

- **key** -- 16, 24, or 32 bytes. Throws `RangeError` if the length is invalid.
- **iv** -- exactly 16 bytes. Must be the same IV that was used for encryption.
  Throws `RangeError` if the length is not 16.
- **ciphertext** -- must be a non-zero multiple of 16 bytes. Throws `RangeError`
  if the length is zero or not a multiple of 16. Also throws `RangeError` if PKCS7
  padding is invalid (which typically indicates the wrong key, wrong IV, or
  corrupted ciphertext).

Returns the decrypted plaintext as a new `Uint8Array`.

---

#### `dispose(): void`

Wipes all key material and intermediate state from WASM memory.

---

### SerpentStream

Chunked authenticated encryption for large payloads. Each chunk is independently
encrypted with Serpent-CTR and authenticated with HMAC-SHA256 using per-chunk
keys derived via HKDF-SHA256. Position binding and truncation detection are
enforced at the key-derivation layer.

Use `SerpentStream` when the payload is large or when holding the entire
plaintext in memory is undesirable. For small/medium payloads where a single
`encrypt()`/`decrypt()` call is sufficient, use `SerpentSeal` instead.

> [!NOTE]
> `SerpentStream` takes a 32-byte key (HKDF handles expansion internally).
> This differs from `SerpentSeal`, which takes 64 bytes.

```typescript
class SerpentStream {
	constructor()
	seal(key: Uint8Array, plaintext: Uint8Array, chunkSize?: number): Uint8Array
	open(key: Uint8Array, ciphertext: Uint8Array): Uint8Array
	dispose(): void
}
```

#### `constructor()`

Creates a new SerpentStream instance. Throws if `init(['serpent', 'sha2'])` has
not been called.

---

#### `seal(key: Uint8Array, plaintext: Uint8Array, chunkSize?: number): Uint8Array`

Encrypts plaintext into a chunked authenticated wire format.

- **key** -- exactly 32 bytes. Throws `RangeError` if not.
- **plaintext** -- any length (including zero).
- **chunkSize** -- optional, default 64KB. Valid range: 1KB to 64KB. Throws
  `RangeError` if outside range.

A fresh random stream nonce is generated internally for each call. Two seals of
the same plaintext with the same key produce different output.

Wire format: `stream_nonce (16) || chunk_size (4, u32_be) || chunk_count (8, u64_be) || chunk_0 || ... || chunk_N-1`

Each chunk on the wire: `ciphertext || hmac_tag (32 bytes)`.

---

#### `open(key: Uint8Array, ciphertext: Uint8Array): Uint8Array`

Verifies authentication and decrypts the chunked wire format. Each chunk's MAC
is verified before decryption (Encrypt-then-MAC). If any chunk fails
authentication, `open()` throws immediately and never returns partial plaintext.

- **key** -- exactly 32 bytes. Must be the same key used for `seal()`.
- **ciphertext** -- the wire format from `seal()`. Throws `RangeError` if too
  short.

---

#### `dispose(): void`

Wipes all key material and intermediate state from WASM memory. Delegates to
internal SerpentCtr, HMAC_SHA256, and HKDF_SHA256 instances.

**Security properties:**

- **Per-chunk EtM** -- HMAC-SHA256 over ciphertext, verified before decrypt.
- **Position binding** -- chunk index encoded in HKDF `info`. Reordering chunks
  produces wrong keys; MAC fails.
- **Truncation detection** -- final chunk derives different keys than any
  intermediate chunk at the same index.
- **Implicit header integrity** -- HKDF `info` embeds the full header. Tampering
  with any header field invalidates every chunk's MAC.
- **Domain separation** -- `"serpent-stream-v1"` prefix prevents key confusion
  with SerpentSeal or other constructions.

> [!IMPORTANT]
> This is a bespoke construction (no external RFC). The compositional security
> argument rests on HKDF (RFC 5869), HMAC-EtM, and Serpent-CTR. See
> [sha2.md](./sha2.md) for HKDF details.

> [!NOTE]
> `sealChunk` and `openChunk` are exported from the serpent submodule for
> internal use by the pool worker. They are not public API -- callers should use
> `SerpentStream` or `SerpentStreamPool`.

---

### SerpentStreamPool

Parallel worker pool for `SerpentStream`. Same wire format, same security
properties, faster on multi-core hardware for large payloads. Each worker owns
its own `serpent.wasm` and `sha2.wasm` instances with isolated linear memory.

`SerpentStream.seal()` and `SerpentStreamPool.seal()` produce compatible wire
formats -- either can decrypt the other's output.

```typescript
class SerpentStreamPool {
	static async create(opts?: StreamPoolOpts): Promise<SerpentStreamPool>
	seal(key: Uint8Array, plaintext: Uint8Array, chunkSize?: number): Promise<Uint8Array>
	open(key: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array>
	dispose(): void
	get size(): number
	get queueDepth(): number
}
```

#### `static async create(opts?: StreamPoolOpts): Promise<SerpentStreamPool>`

Creates a new pool. Requires `init(['serpent', 'sha2'])` to have been called.
Compiles both WASM modules once and distributes them to all workers.

- **opts.workers** -- number of workers to spawn. Default:
  `navigator.hardwareConcurrency ?? 4`.

Uses a static factory pattern because worker initialization is async (WASM
compilation and instantiation happen per worker).

---

#### `seal(key, plaintext, chunkSize?)`

Same parameters as `SerpentStream.seal()`, but returns a `Promise`. Key
derivation happens on the main thread; chunk encryption is parallelised across
workers.

---

#### `open(key, ciphertext)`

Same parameters as `SerpentStream.open()`, but returns a `Promise`. If any chunk
fails authentication, the promise rejects immediately -- no partial plaintext is
returned.

---

#### `dispose()`

Terminates all workers. Rejects all pending and queued jobs. Must be called to
release worker resources when the pool is no longer needed.

---

### SerpentStreamSealer / SerpentStreamOpener

Incremental streaming AEAD — seal and open one chunk at a time without holding
the full message in memory. Unlike `SerpentStream` (which is one-shot),
`SerpentStreamSealer` produces chunks as data arrives and `SerpentStreamOpener`
authenticates and decrypts them individually.

**Wire format:**
```
header:  nonce (16) || chunkSize_u32be (4)                = 20 bytes
chunk:   IV (16) || CBC_ciphertext (PKCS7-padded) || HMAC-SHA256 (32)
```

Per-chunk keys are derived via HKDF-SHA256 from the stream key and a `chunkInfo`
blob binding the stream nonce, chunk size, chunk index, and `isLast` flag. Each
chunk is independently authenticated and position-bound — reordering, truncation,
and cross-stream splicing are all detected.

> [!NOTE]
> `SerpentStreamSealer` requires a 64-byte key (same as `SerpentSeal`). HKDF
> derives a fresh `encKey` + `macKey` pair for every chunk.

> [!IMPORTANT]
> The sealer produces a 20-byte header that **must** be transmitted to the opener
> before any chunks. The opener is initialized with this header.

```typescript
class SerpentStreamSealer {
	constructor(key: Uint8Array, chunkSize?: number)
	header(): Uint8Array        // call once before seal() — returns 20 bytes
	seal(plaintext: Uint8Array): Uint8Array   // exactly chunkSize bytes
	final(plaintext: Uint8Array): Uint8Array  // <= chunkSize bytes; wipes on return
	dispose(): void             // abort mid-stream; wipes without final chunk
}

class SerpentStreamOpener {
	constructor(key: Uint8Array, header: Uint8Array)
	open(chunk: Uint8Array): Uint8Array  // throws on auth failure or post-final
	dispose(): void
}
```

#### Sealer state machine

| State | Valid calls |
|---|---|
| `fresh` | `header()`, `dispose()` |
| `sealing` | `seal()`, `final()`, `dispose()` |
| `dead` | `dispose()` (no-op) |

`header()` transitions `fresh → sealing`. `final()` seals the last chunk, wipes
all key material, and transitions to `dead`. `dispose()` wipes and transitions to
`dead` from any state — use it to abort a stream before `final()` is called.

Calling `header()` twice, `seal()` before `header()`, or any method after `final()`
all throw immediately.

---

#### Opener state machine

The opener is ready as soon as it is constructed. It calls `open()` for each
chunk in order. Once a chunk with `isLast` set passes authentication, the opener
wipes its key material and transitions to `dead`. Subsequent `open()` calls throw.

`dispose()` wipes and marks the instance dead from any state.

---

#### `constructor(key, chunkSize?)`

- **key** — 64-byte key. Throws `RangeError` if wrong length.
- **chunkSize** — bytes per chunk. Must be 1024–65536. Default: 65536. Throws
  `RangeError` if out of range.

---

#### `header()`

Returns the 20-byte stream header (`nonce || u32be(chunkSize)`). Must be called
once before the first `seal()`. Throws if called a second time or after `final()`.

---

#### `seal(plaintext)`

Seals one chunk. **Plaintext must be exactly `chunkSize` bytes.** Returns
`IV (16) || ciphertext || HMAC (32)`. Throws `RangeError` if wrong size. Throws
if called before `header()` or after `final()`.

---

#### `final(plaintext)`

Seals the last chunk. Plaintext may be 0–`chunkSize` bytes (partial chunk is
valid). After producing output, wipes all key material and marks the sealer dead.
Throws `RangeError` if plaintext exceeds `chunkSize`.

---

#### `dispose()` (sealer)

Aborts the stream. Wipes key material without producing a final chunk. The opener
will see an incomplete stream and throw when it detects a missing final chunk.
Safe to call after `final()` — no-op if already dead.

---

#### `constructor(key, header)` (opener)

- **key** — 64-byte key. Throws `RangeError` if wrong length.
- **header** — 20-byte stream header from `sealer.header()`. Throws `RangeError`
  if wrong length.

---

#### `open(chunk)`

Authenticates and decrypts one chunk. Throws `Error` on authentication failure.
Throws `Error` if called after the final chunk has already been opened. Returns
plaintext bytes (PKCS7 padding stripped).

---

#### `dispose()` (opener)

Wipes key material. Safe to call at any point — use to abort opening a stream
early.

---

## Usage Examples

### Example 1: SerpentSeal (authenticated encryption)

```typescript
import { init, SerpentSeal, randomBytes } from 'leviathan-crypto';

await init(['serpent', 'sha2']);

// 64-byte key: 32 bytes encryption + 32 bytes MAC
const key = randomBytes(64);

const seal = new SerpentSeal();

const plaintext  = new TextEncoder().encode('Authenticated secret message.');
const ciphertext = seal.encrypt(key, plaintext);
const decrypted  = seal.decrypt(key, ciphertext);

console.log(new TextDecoder().decode(decrypted));
// "Authenticated secret message."

seal.dispose();
```

### Example 2: CTR mode (advanced)

Advanced use. For authenticated encryption, use `SerpentSeal`.

Use `SerpentCtr` to encrypt data of any length. CTR mode produces ciphertext
that is the same length as the plaintext -- no padding overhead.

```typescript
import { init, SerpentCtr, randomBytes } from 'leviathan-crypto';

await init(['serpent']);

const key   = randomBytes(32); // 256-bit key
const nonce = randomBytes(16); // 16-byte nonce -- NEVER reuse with the same key

const ctr = new SerpentCtr({ dangerUnauthenticated: true });

// Encrypt
ctr.beginEncrypt(key, nonce);
const ciphertext1 = ctr.encryptChunk(new TextEncoder().encode('Hello, '));
const ciphertext2 = ctr.encryptChunk(new TextEncoder().encode('world!'));

// Decrypt (same key and nonce)
ctr.beginDecrypt(key, nonce);
const plain1 = ctr.decryptChunk(ciphertext1);
const plain2 = ctr.decryptChunk(ciphertext2);

console.log(new TextDecoder().decode(plain1)); // "Hello, "
console.log(new TextDecoder().decode(plain2)); // "world!"

// Wipe key material
ctr.dispose();
```

> [!IMPORTANT]
> CTR mode is unauthenticated. An attacker can tamper with the
> ciphertext without detection. Use `SerpentSeal` for authenticated encryption.

### Example 3: CBC mode (advanced)

Advanced use. For authenticated encryption, use `SerpentSeal`.

Use `SerpentCbc` for message-level encryption with automatic PKCS7 padding.

```typescript
import { init, SerpentCbc, randomBytes } from 'leviathan-crypto';

await init(['serpent']);

const key = randomBytes(32); // 256-bit key
const iv  = randomBytes(16); // Random IV -- must be unique per message

const cbc = new SerpentCbc({ dangerUnauthenticated: true });

// Encrypt
const plaintext  = new TextEncoder().encode('This is a secret message.');
const ciphertext = cbc.encrypt(key, iv, plaintext);

// Decrypt
const decrypted = cbc.decrypt(key, iv, ciphertext);
console.log(new TextDecoder().decode(decrypted)); // "This is a secret message."

// Wipe key material
cbc.dispose();
```

> [!IMPORTANT]
> CBC mode is unauthenticated. Use `SerpentSeal` for authenticated encryption.

### Example 4: SerpentStream (chunked authenticated encryption)

Use `SerpentStream` for large payloads where holding the entire plaintext in
memory is undesirable.

```typescript
import { init, SerpentStream, randomBytes } from 'leviathan-crypto';

await init(['serpent', 'sha2']);

const key = randomBytes(32); // 32-byte key (HKDF handles expansion)

const stream = new SerpentStream();

const plaintext  = new Uint8Array(1024 * 1024); // 1 MB
crypto.getRandomValues(plaintext);

const ciphertext = stream.seal(key, plaintext);       // default 64KB chunks
const decrypted  = stream.open(key, ciphertext);

// decrypted is byte-identical to plaintext

stream.dispose();
```

### Example 5: SerpentStreamPool (parallel chunked encryption)

Use `SerpentStreamPool` for maximum throughput on multi-core hardware.

```typescript
import { init, SerpentStreamPool, randomBytes } from 'leviathan-crypto';

await init(['serpent', 'sha2']);

const pool = await SerpentStreamPool.create({ workers: 4 });

const key       = randomBytes(32);
const plaintext = new Uint8Array(10 * 1024 * 1024); // 10 MB

const ciphertext = await pool.seal(key, plaintext);
const decrypted  = await pool.open(key, ciphertext);

// decrypted is byte-identical to plaintext

pool.dispose(); // terminates workers
```

### Example 6: SerpentStreamSealer / SerpentStreamOpener (incremental streaming)

Use `SerpentStreamSealer` when data arrives in chunks and you cannot buffer the
entire plaintext before encrypting — network streams, file processors, live feeds.

```typescript
import { init, SerpentStreamSealer, SerpentStreamOpener, randomBytes } from 'leviathan-crypto';

await init(['serpent', 'sha2']);

const key       = randomBytes(64);  // 64-byte key
const chunkSize = 65536;            // 64 KB chunks

// ── Seal side ────────────────────────────────────────────────────────────────

const sealer = new SerpentStreamSealer(key, chunkSize);
const header = sealer.header();  // transmit this to the opener first

// seal() as data arrives — each chunk must be exactly chunkSize bytes
const chunk0 = sealer.seal(plaintext0);
const chunk1 = sealer.seal(plaintext1);

// final() for the last chunk — may be shorter than chunkSize
const lastChunk = sealer.final(lastPlaintext);
// sealer is now dead — key material wiped

// ── Open side ────────────────────────────────────────────────────────────────

const opener = new SerpentStreamOpener(key, header);

const pt0  = opener.open(chunk0);
const pt1  = opener.open(chunk1);
const ptN  = opener.open(lastChunk);  // opener detects isLast, wipes on return
// opener is now dead

// Truncation and reordering are detected — open() throws on auth failure
```

To abort a stream mid-way (e.g. on connection drop):

```typescript
sealer.dispose();  // wipes key material without producing a final chunk
// opener will throw when it receives no more chunks
```

### Example 7: Raw block operations (low-level)

Use the `Serpent` class for single 16-byte block operations. This is the lowest
level API, most users should use `SerpentSeal` instead.

```typescript
import { init, Serpent } from 'leviathan-crypto';

await init(['serpent']);

const cipher = new Serpent();

// Load a 256-bit key (32 bytes)
const key = new Uint8Array(32);
crypto.getRandomValues(key);
cipher.loadKey(key);

// Encrypt a 16-byte block
const plaintext = new Uint8Array([
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
]);
const ciphertext = cipher.encryptBlock(plaintext);

// Decrypt it back
const decrypted = cipher.decryptBlock(ciphertext);
// decrypted is identical to plaintext

// Wipe key material from memory when done
cipher.dispose();
```

---

## Error Conditions

| Condition | Error type | Message |
|-----------|-----------|---------|
| `SerpentSeal` constructed before `init(['serpent', 'sha2'])` | `Error` | `leviathan-crypto: call init(['serpent', 'sha2']) before using SerpentSeal` |
| `SerpentSeal` key is not 64 bytes | `RangeError` | `SerpentSeal key must be 64 bytes (got N)` |
| `SerpentSeal` data too short for decrypt | `RangeError` | `SerpentSeal ciphertext too short` |
| `SerpentSeal` authentication failed | `Error` | `SerpentSeal: authentication failed` |
| `init(['serpent'])` not called before constructing `Serpent` | `Error` | `leviathan-crypto: call init(['serpent']) before using this class` |
| `SerpentCbc` constructed without `{ dangerUnauthenticated: true }` | `Error` | `leviathan-crypto: SerpentCbc is unauthenticated — use SerpentSeal instead. To use SerpentCbc directly, pass { dangerUnauthenticated: true }.` |
| `SerpentCtr` constructed without `{ dangerUnauthenticated: true }` | `Error` | `leviathan-crypto: SerpentCtr is unauthenticated — use SerpentSeal instead. To use SerpentCtr directly, pass { dangerUnauthenticated: true }.` |
| Key is not 16, 24, or 32 bytes (`Serpent.loadKey`) | `RangeError` | `key must be 16, 24, or 32 bytes (got N)` |
| Key is not 16, 24, or 32 bytes (`SerpentCbc`) | `RangeError` | `Serpent key must be 16, 24, or 32 bytes (got N)` |
| Key is not 16, 24, or 32 bytes (`SerpentCtr`) | `RangeError` | `key must be 16, 24, or 32 bytes` |
| Block is not 16 bytes (`Serpent`) | `RangeError` | `block must be 16 bytes (got N)` |
| Nonce is not 16 bytes (`SerpentCtr`) | `RangeError` | `nonce must be 16 bytes (got N)` |
| Chunk exceeds buffer size (`SerpentCtr`) | `RangeError` | `chunk exceeds maximum size of N bytes — split into smaller chunks` |
| IV is not 16 bytes (`SerpentCbc`) | `RangeError` | `CBC IV must be 16 bytes (got N)` |
| Ciphertext length is zero or not a multiple of 16 (`SerpentCbc.decrypt`) | `RangeError` | `ciphertext length must be a non-zero multiple of 16` |
| Invalid PKCS7 padding on decrypt (`SerpentCbc.decrypt`) | `RangeError` | `invalid PKCS7 padding` |
| `SerpentStream` constructed before `init(['serpent', 'sha2'])` | `Error` | `leviathan-crypto: call init(['serpent', 'sha2']) before using SerpentStream` |
| `SerpentStream` key is not 32 bytes | `RangeError` | `SerpentStream key must be 32 bytes (got N)` |
| `SerpentStream` chunkSize out of range | `RangeError` | `SerpentStream chunkSize must be 1024..65536 (got N)` |
| `SerpentStream` ciphertext too short | `RangeError` | `SerpentStream: ciphertext too short` |
| `SerpentStream` authentication failed | `Error` | `SerpentStream: authentication failed` |
| `SerpentStreamPool.create()` before `init(['serpent', 'sha2'])` | `Error` | `leviathan-crypto: call init(['serpent', 'sha2']) before using SerpentStreamPool` |
| `SerpentStreamPool` methods after `dispose()` | `Error` | `leviathan-crypto: pool is disposed` |
| `SerpentStreamSealer` constructed before `init(['serpent', 'sha2'])` | `Error` | `leviathan-crypto: call init(['serpent']) before using SerpentStreamSealer` |
| `SerpentStreamSealer` key is not 64 bytes | `RangeError` | `SerpentStreamSealer key must be 64 bytes (got N)` |
| `SerpentStreamSealer` chunkSize out of range | `RangeError` | `SerpentStreamSealer chunkSize must be 1024..65536 (got N)` |
| `SerpentStreamSealer.header()` called twice | `Error` | `SerpentStreamSealer: header() already called` |
| `SerpentStreamSealer.seal()` before `header()` | `Error` | `SerpentStreamSealer: call header() first` |
| `SerpentStreamSealer.seal()` or `final()` after `final()` or `dispose()` | `Error` | `SerpentStreamSealer: stream is closed` |
| `SerpentStreamSealer.seal()` wrong plaintext size | `RangeError` | `SerpentStreamSealer: seal() requires exactly N bytes (got M)` |
| `SerpentStreamSealer.final()` plaintext exceeds chunkSize | `RangeError` | `SerpentStreamSealer: final() plaintext exceeds chunkSize (got N)` |
| `SerpentStreamOpener` constructed before `init(['serpent', 'sha2'])` | `Error` | `leviathan-crypto: call init(['serpent']) before using SerpentStreamOpener` |
| `SerpentStreamOpener` key is not 64 bytes | `RangeError` | `SerpentStreamOpener key must be 64 bytes (got N)` |
| `SerpentStreamOpener` header is not 20 bytes | `RangeError` | `SerpentStreamOpener header must be 20 bytes (got N)` |
| `SerpentStreamOpener.open()` authentication failed | `Error` | `SerpentStreamOpener: authentication failed` |
| `SerpentStreamOpener.open()` after stream closed | `Error` | `SerpentStreamOpener: stream is closed` |

---

> ## Cross-References
>
> - [README.md](./README.md) — project overview and quick-start guide
> - [architecture.md](./architecture.md) — architecture overview, module relationships, buffer layouts, and build pipeline
> - [asm_serpent.md](./asm_serpent.md) — WASM implementation details and buffer layout
> - [serpent_reference.md](./serpent_reference.md) — algorithm specification, S-boxes, linear transform, and known attacks
> - [serpent_audit.md](./serpent_audit.md) — security audit findings (correctness, side-channel analysis)
> - [chacha20.md](./chacha20.md) — XChaCha20Poly1305 authenticated encryption (alternative AEAD)
> - [sha2.md](./sha2.md) — HMAC-SHA256 and HKDF used internally by SerpentSeal and SerpentStream
> - [types.md](./types.md) — `Blockcipher`, `Streamcipher`, and `AEAD` interfaces implemented by Serpent classes
> - [utils.md](./utils.md) — `constantTimeEqual`, `wipe`, `randomBytes` used by Serpent wrappers

