# Fortuna: Cryptographically Secure Pseudorandom Number Generator (CSPRNG)

> [!NOTE]
> A CSPRNG that continuously collects entropy from the environment and generates
> cryptographically secure random bytes, backed by WASM Serpent-256 and SHA-256.

## Overview

A cryptographically secure pseudorandom number generator (CSPRNG) produces random
bytes that are indistinguishable from true randomness to any observer, even one
with significant computational resources. This matters because many security
operations -- generating encryption keys, initialization vectors, nonces, tokens
-- require randomness that an attacker cannot predict. If an attacker can predict
the output of your random number generator, they can predict your keys, and your
encryption provides no protection.

Fortuna is a CSPRNG designed by Bruce Schneier and Niels Ferguson, published in
*Practical Cryptography* (2003). It continuously collects entropy from multiple
sources -- mouse movements, keyboard events, system timers, OS randomness -- and
feeds that entropy into 32 independent pools. When you request random bytes,
Fortuna combines pool contents and uses them to reseed an internal generator
built on Serpent-256 (block cipher) and SHA-256 (hash function). Both primitives
run entirely in WebAssembly.

Why use Fortuna instead of `crypto.getRandomValues()`? The OS random source is
good, and Fortuna seeds itself from it on creation. But Fortuna adds two
properties on top. First, **forward secrecy**: after every call to `get()`, the
internal generation key is replaced, so compromising the current state does not
reveal any past outputs. Second, **defense-in-depth entropy pooling**: Fortuna
collects entropy from many independent sources and distributes it across 32 pools
with exponentially increasing reseed intervals, making it resilient to entropy
estimation attacks and individual source failures.

Fortuna is the only class in leviathan-crypto that requires two WASM modules.
You must initialize both `serpent` and `sha2` before creating an instance, and
you must use the `Fortuna.create()` static factory rather than `new Fortuna()`.

---

## Security Notes

- **Forward secrecy** -- The generation key is replaced after every call to
  `get()`. If an attacker compromises the internal state at time T, they cannot
  reconstruct any output produced before time T.

- **32 entropy pools** -- Entropy is distributed across 32 independent pools
  using round-robin assignment. Pool 0 is used on every reseed, pool 1 on every
  second reseed, pool 2 on every fourth, and so on. This exponential schedule
  means that even if an attacker can observe or influence some entropy sources,
  higher-numbered pools accumulate enough entropy over time to produce a strong
  reseed eventually.

- **Immediate usability** -- Fortuna seeds itself from `crypto.getRandomValues()`
  (browser) or `crypto.randomBytes()` (Node.js) during creation, so it is
  immediately usable. You do not need to wait for entropy to accumulate before
  calling `get()`.

- **Browser entropy sources** -- mouse movements, keyboard events, click events,
  scroll position, touch events, device motion and orientation,
  `performance.now()` timing, DOM content hash, and periodic
  `crypto.getRandomValues()`.

- **Node.js entropy sources** -- `crypto.randomBytes()`, `process.hrtime` (nanosecond
  timing jitter), `process.cpuUsage()`, `process.memoryUsage()`, `os.loadavg()`,
  `os.freemem()`.

- **Wipe state when done** -- Call `stop()` when you are finished with the
  instance. This wipes the generation key and counter from memory and stops all
  background entropy collectors. Key material should not persist longer than
  necessary.

- **Output quality depends on entropy** -- The initial seed from the OS random
  source is strong. Over time, the additional entropy collectors improve the
  state further. In environments with limited user interaction (headless servers,
  automated tests), fewer entropy sources contribute, but the OS random seed
  still provides a solid baseline.

---

## API Reference

### `Fortuna.create(opts?)`

Static async factory. Returns a `Promise<Fortuna>`. The returned instance is
guaranteed to be seeded -- `create()` forces an initial reseed before resolving,
so `get()` is immediately usable.

```typescript
static async create(opts?: {
	msPerReseed?: number;
	entropy?: Uint8Array;
}): Promise<Fortuna>
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `opts.msPerReseed` | `number` | `100` | Minimum milliseconds between reseeds. |
| `opts.entropy` | `Uint8Array` | -- | Optional extra entropy to mix in during creation. |

Throws if `init({ serpent: serpentWasm, sha2: sha2Wasm })` has not been called.

Direct construction with `new Fortuna()` is not possible -- the constructor is
private. Always use `Fortuna.create()`.

---

### `get(length)`

Generate `length` random bytes.

```typescript
get(length: number): Uint8Array
```

Returns a `Uint8Array` of the requested length. The instance is always seeded
after `create()` resolves, so this method is guaranteed to return data.

After producing the output, the generation key is replaced with fresh
pseudorandom material. This is the forward secrecy mechanism -- the key used to
produce this output no longer exists.

---

### `addEntropy(entropy)`

Manually add entropy to the pools.

```typescript
addEntropy(entropy: Uint8Array): void
```

Use this to feed application-specific randomness into the generator. The entropy
is distributed across pools using round-robin assignment. Each call advances to
the next pool.

---

### `getEntropy()`

Get the estimated available entropy in bytes.

```typescript
getEntropy(): number
```

Returns the estimated total entropy accumulated across all pools, in bytes. This
is an estimate, not a guarantee -- it reflects the sum of entropy credits assigned
by each collector.

---

### `stop()`

Permanently dispose this Fortuna instance.

```typescript
stop(): void
```

> [!WARNING]
> Do not attempt to reuse a stopped instance. `stop()` is a permanent dispose
> operation. If a new Fortuna instance is needed, call `Fortuna.create()`.

Call this when you are done with the Fortuna instance. `stop()`:
- Removes all browser event listeners
- Clears all background timers (Node.js stats collection, periodic crypto random)
- Zeroes the generation key and counter
- Resets the reseed counter to 0
- Marks the instance as disposed

All subsequent method calls (`get()`, `addEntropy()`, `getEntropy()`, `stop()`)
on a disposed instance throw immediately:
```
Error: Fortuna instance has been disposed
```

There is no `start()` or restart capability.

---

## Usage Examples

### Basic usage -- generate random bytes

```typescript
import { init, Fortuna } from 'leviathan-crypto'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

// Initialize both WASM modules that Fortuna depends on
await init({ serpent: serpentWasm, sha2: sha2Wasm })

// Create the CSPRNG
const rng = await Fortuna.create()

// Generate 32 random bytes (e.g., for an encryption key)
const key = rng.get(32)

// Generate 12 random bytes (e.g., for a nonce)
const nonce = rng.get(12)

// Clean up when done -- wipes key material from memory
rng.stop()
```

### Adding custom entropy

```typescript
import { init, Fortuna, utf8ToBytes } from 'leviathan-crypto'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await init({ serpent: serpentWasm, sha2: sha2Wasm })
const rng = await Fortuna.create()

// Feed application-specific data as additional entropy.
// This supplements (never replaces) the automatic entropy collection.
const userData = utf8ToBytes(crypto.randomUUID())
rng.addEntropy(userData)

// Server-side: feed in request-specific data
const requestEntropy = new Uint8Array(16)
crypto.getRandomValues(requestEntropy)
rng.addEntropy(requestEntropy)

const token = rng.get(32)
rng.stop()
```

### Browser with automatic entropy collection

```typescript
import { init, Fortuna } from 'leviathan-crypto'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await init({ serpent: serpentWasm, sha2: sha2Wasm })

// Fortuna automatically registers browser event listeners on creation:
// - mousemove (throttled to 50ms)
// - keydown
// - click
// - scroll
// - touchstart, touchmove, touchend
// - devicemotion, deviceorientation, orientationchange
//
// Every user interaction feeds entropy into the pools.
// No manual setup is needed -- it starts collecting immediately.

const rng = await Fortuna.create()

// The longer the user interacts with the page before you generate,
// the more entropy has been accumulated. But the initial OS seed
// is strong enough for immediate use.
document.querySelector('#generate')?.addEventListener('click', () => {
	const bytes = rng.get(32)
	console.log('Generated:', bytes)
})

// When the page unloads or the component unmounts, stop the collectors
window.addEventListener('beforeunload', () => rng.stop())
```

### Providing initial entropy at creation

```typescript
import { init, Fortuna } from 'leviathan-crypto'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await init({ serpent: serpentWasm, sha2: sha2Wasm })

// You can pass extra entropy at creation time.
// This is mixed into the pools during initialization, before the
// generator is first seeded.
const extraSeed = new Uint8Array(64)
crypto.getRandomValues(extraSeed)

const rng = await Fortuna.create({ entropy: extraSeed })
const bytes = rng.get(32)
rng.stop()
```

---

## Error Conditions

| Condition | What happens |
|-----------|-------------|
| `init()` not called | `Fortuna.create()` throws: `leviathan-crypto: call init({ serpent: ..., sha2: ... }) before using Fortuna` |
| Only one module initialized | Same error -- both `serpent` and `sha2` must be initialized. |
| `new Fortuna()` | Compile-time error -- the constructor is private. TypeScript will not allow it. |
| Any method after `stop()` | Throws: `Fortuna instance has been disposed`. The instance is permanently disposed. |

---

## How It Works (Simplified)

For readers who want to understand what Fortuna does internally, without needing
to read the spec:

1. **Entropy collection** -- Background listeners and timers capture small,
   unpredictable measurements (mouse coordinates, nanosecond timings, memory
   usage) and feed them into 32 separate pools via SHA-256 hash chaining.

2. **Reseed** -- When pool 0 has accumulated enough entropy and enough time has
   passed since the last reseed, Fortuna combines the contents of eligible pools
   (determined by the reseed counter) into a seed, and derives a new generation
   key: `genKey = SHA-256(genKey || seed)`.

3. **Generation** -- To produce output, the generator encrypts an incrementing
   counter with Serpent-256 in ECB mode using the current generation key. The
   output is the concatenation of encrypted counter blocks, truncated to the
   requested length.

4. **Key replacement** -- Immediately after producing output, the generation key
   is replaced with fresh pseudorandom blocks. The old key is gone. This is what
   provides forward secrecy.

---

> ## Cross-References
>
> - [index](./README.md) — Project Documentation index
> - [architecture](./architecture.md) — architecture overview, module relationships, buffer layouts, and build pipeline
> - [serpent](./serpent.md): Serpent-256 TypeScript API (Fortuna uses Serpent ECB internally)
> - [sha2](./sha2.md): SHA-256 TypeScript API (Fortuna uses SHA-256 for entropy accumulation)
> - [asm_serpent](./asm_serpent.md): Serpent-256 WASM implementation details
> - [asm_sha2](./asm_sha2.md): SHA-256 WASM implementation details
> - [utils](./utils.md): `randomBytes()` for simpler random generation needs
