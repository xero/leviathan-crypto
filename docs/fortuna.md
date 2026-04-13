<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### Fortuna CSPRNG

A CSPRNG that continuously collects entropy from the environment and generates cryptographically secure random bytes. The cipher and hash primitives are pluggable; you pick which pair to use at create time.

> ### Table of Contents
> - [Overview](#overview)
> - [Pluggable primitives](#pluggable-primitives)
> - [Spec deviations](#spec-deviations)
> - [Security Notes](#security-notes)
> - [API Reference](#api-reference)
> - [Usage Examples](#usage-examples)
> - [Error Conditions](#error-conditions)
> - [How It Works (Simplified)](#how-it-works-simplified)
> - [Coexistence with raw ciphers](#coexistence-with-raw-ciphers)
> - [Cross-References](#cross-references)

---

## Overview

A cryptographically secure pseudorandom number generator (CSPRNG) produces
random bytes that are indistinguishable from true randomness to any observer,
even one with significant computational resources. This matters because many
security operations require unpredictable randomness: generating encryption
keys, initialization vectors, nonces, and tokens. If an attacker can predict
the output of your random number generator, they can predict your keys, and
your encryption provides no protection.

Fortuna is a CSPRNG designed by Bruce Schneier and Niels Ferguson, published
in *Practical Cryptography* (2003). It continuously collects entropy from
multiple sources (mouse movements, keyboard events, system timers, OS
randomness) and feeds that entropy into 32 independent pools. When you
request random bytes, Fortuna combines pool contents and uses them to reseed
an internal generator built on a cipher-as-PRF construction and a hash
function. You pick which cipher and hash at create time.

Fortuna adds two properties on top of `crypto.getRandomValues()`. First,
**forward secrecy**: after every call to `get()`, the internal generation
key is replaced, so compromising the current state does not reveal any past
outputs. Second, **defense-in-depth entropy pooling**: Fortuna collects
entropy from many independent sources and distributes it across 32 pools
with exponentially increasing reseed intervals, making it resilient to
entropy estimation attacks and individual source failures.

The original spec uses AES-256 in counter mode with SHA-256. This
implementation lets you pick from Serpent-256 or ChaCha20 for the generator,
paired with SHA-256 or SHA3-256 for the hash. See
[Pluggable primitives](#pluggable-primitives) for the available combinations
and [Spec deviations](#spec-deviations) for what changes when you pick
something other than the original pair.

---

## Pluggable primitives

Fortuna takes two primitives at create time:

- A **`Generator`**, the cipher-as-PRF that produces output blocks from `(key, counter)`.
- A **`HashFn`**, the stateless hash used for accumulator chaining and reseed key derivation.

Both ship as plain const objects from each cipher and hash module. The const
pattern matches `SerpentCipher` and `XChaCha20Cipher` in the AEAD layer.

| Generator           | Source path                  | `keySize` | Cipher backend           |
| ------------------- | ---------------------------- | --------- | ------------------------ |
| `SerpentGenerator`  | `leviathan-crypto/serpent`   | 32        | Serpent-256 ECB          |
| `ChaCha20Generator` | `leviathan-crypto/chacha20`  | 32        | ChaCha20 with zero nonce |

| Hash           | Source path                | `outputSize` | Hash backend |
| -------------- | -------------------------- | ------------ | ------------ |
| `SHA256Hash`   | `leviathan-crypto/sha2`    | 32           | SHA-256      |
| `SHA3_256Hash` | `leviathan-crypto/sha3`    | 32           | SHA3-256     |

All four combinations are valid because every shipped `Generator` has
`keySize: 32` and every shipped `HashFn` has `outputSize: 32`.
`Fortuna.create()` asserts `hash.outputSize === generator.keySize` and
throws `RangeError` if you pair primitives of different sizes.

The motivation for pluggability is bundle size. Earlier versions of Fortuna
pinned Serpent + SHA-256, which meant a chacha-only consumer paid for
Serpent's 123 KB WASM module just to use the CSPRNG. With pluggable
primitives, an XChaCha20-Poly1305 application can pair `Fortuna` with
`ChaCha20Generator` + `SHA256Hash` and the bundle never sees Serpent.

---

## Spec deviations

The original Fortuna spec (Ferguson and Schneier, *Practical Cryptography*
2003) is concrete about its choice of primitives:

- §9.4 specifies AES-256 in counter mode as the generator.
- §9.5 specifies SHA-256 for the accumulator pools and reseed key derivation.

This library replaces both with a pluggable contract. The deviations:

1. **Generator can be Serpent-256 or ChaCha20.** Serpent-256 is a 256-bit-key
   block cipher with the same shape as AES; substituting it changes the
   underlying permutation but preserves the counter-mode-PRF construction.
   ChaCha20 is a stream cipher whose block function is itself a strong PRF
   on `(key, nonce, counter)`; we fix the nonce to zero and treat the block
   counter as Fortuna's generator counter. Both substitutions are valid in
   the sense that the security argument for Fortuna's generator depends on
   the underlying primitive being a strong PRF, which Serpent-256 and
   ChaCha20 both are under standard assumptions.

2. **Hash can be SHA-256 or SHA3-256.** SHA3-256 is a sponge-based hash; the
   security properties Fortuna requires from the hash (collision resistance,
   second-preimage resistance, output indistinguishable from random) hold
   for both.

3. **Hash output size is required to match generator key size in v2.2.0.**
   The reseed step `genKey = hash(genKey || seed)` writes the hash output
   directly into the generator key slot, with no KDF layer. This forbids
   exotic combinations such as SHA-512 paired with a 32-byte-key generator.
   If a real use case for size mismatches appears later, an HKDF mode can
   be added without breaking existing pairings.

The pool-selection schedule, the 32-pool count, the 64-bit reseed threshold,
the 100ms reseed interval, and the entropy-credit constants are unchanged
from the spec.

---

## Security Notes

**Forward secrecy.** The generation key is replaced after every call to
`get()`. If an attacker compromises the internal state at time T, they
cannot reconstruct any output produced before time T.

**32 entropy pools.** Entropy is distributed across 32 independent pools
using round-robin assignment. Pool 0 is used on every reseed, pool 1 on
every second reseed, pool 2 on every fourth, and so on. This exponential
schedule means that even if an attacker can observe or influence some
entropy sources, higher-numbered pools accumulate enough entropy over time
to produce a strong reseed eventually.

**Immediate usability.** Fortuna seeds itself from `crypto.getRandomValues()`
(browser) or `crypto.randomBytes()` (Node.js) during creation. `create()`
asserts that pool 0 received at least 64 bits of entropy from the OS source
before resolving, and throws if no working entropy source is available. You
do not need to wait for entropy to accumulate before calling `get()`.

**Browser entropy sources.** Mouse movements, keyboard events, click events,
scroll position, touch events, device motion and orientation,
`performance.now()` timing, DOM content hash, and periodic
`crypto.getRandomValues()`.

**Node.js entropy sources.** `crypto.randomBytes()`, `process.hrtime`
(nanosecond timing jitter), `process.cpuUsage()`, `process.memoryUsage()`,
`os.loadavg()`, `os.freemem()`.

**Wipe state when done.** Call `stop()` when you are finished with the
instance. This wipes the generation key and counter from JavaScript memory,
calls `wipeBuffers()` on every WASM module the chosen `Generator` and
`HashFn` touched, and stops all background entropy collectors. Key material
should not persist longer than necessary.

**Output quality depends on entropy.** The initial seed from the OS random
source is strong. Over time the additional entropy collectors improve the
state further. In environments with limited user interaction (headless
servers, automated tests), fewer entropy sources contribute, but the OS
random seed still provides a solid baseline.

---

## API Reference

### `Fortuna.create(opts)`

Static async factory. Returns a `Promise<Fortuna>`. The returned instance is
guaranteed to be seeded. `create()` forces an initial reseed before
resolving, so `get()` is immediately usable.

```typescript
static async create(opts: {
    generator: Generator;
    hash: HashFn;
    msPerReseed?: number;
    entropy?: Uint8Array;
}): Promise<Fortuna>
```

| Parameter          | Type         | Default  | Description |
|--------------------|--------------|----------|-------------|
| `opts.generator`   | `Generator`  | required | Cipher-as-PRF backing the generator. `SerpentGenerator` or `ChaCha20Generator`. |
| `opts.hash`        | `HashFn`     | required | Stateless hash for accumulator and reseed. `SHA256Hash` or `SHA3_256Hash`. |
| `opts.msPerReseed` | `number`     | `100`    | Minimum milliseconds between reseeds. |
| `opts.entropy`     | `Uint8Array` |          | Optional extra entropy mixed in during creation. |

Throws `TypeError` if `opts.generator` or `opts.hash` is missing. Throws
`RangeError` if `opts.hash.outputSize !== opts.generator.keySize`. Throws
if any required WASM module has not been initialized via `init()`. Throws
if no working entropy source is available at create time.

Direct construction with `new Fortuna()` is not possible. The constructor
is private. Always use `Fortuna.create()`.

---

### `get(length)`

Generate `length` random bytes.

```typescript
get(length: number): Uint8Array
```

Returns a `Uint8Array` of the requested length. The instance is always
seeded after `create()` resolves, so this method is guaranteed to return
data.

After producing the output, the generation key is replaced with fresh
pseudorandom material. This is the forward secrecy mechanism. The key used
to produce this output no longer exists.

---

### `addEntropy(entropy)`

Manually add entropy to the pools.

```typescript
addEntropy(entropy: Uint8Array): void
```

Use this to feed application-specific randomness into the generator. The
entropy is distributed across pools using round-robin assignment. Each call
advances to the next pool.

---

### `getEntropy()`

Get the estimated available entropy in bytes.

```typescript
getEntropy(): number
```

Returns the estimated total entropy accumulated across all pools, in bytes.
This is an estimate, not a guarantee. It reflects the sum of entropy credits
assigned by each collector.

---

### `stop()`

Permanently dispose this Fortuna instance.

```typescript
stop(): void
```

> [!WARNING]
> Do not attempt to reuse a stopped instance. `stop()` is a permanent
> dispose operation. If a new Fortuna instance is needed, call
> `Fortuna.create()`.

Call this when you are done with the Fortuna instance. `stop()`:

- Marks the instance as disposed (first, before any operation that can throw).
- Removes all browser event listeners.
- Clears all background timers (Node.js stats collection, periodic crypto random).
- Zeroes the generation key and the generation counter.
- Zeroes every pool-hash chain value (all 32 pools).
- Resets the reseed counter to 0.
- Calls `wipeBuffers()` on every WASM module the chosen `Generator` and `HashFn` touched.

All subsequent method calls (`get()`, `addEntropy()`, `getEntropy()`,
`stop()`) on a disposed instance throw immediately:

```
Error: Fortuna instance has been disposed
```

The WASM `wipeBuffers()` step is best-effort. If a stateful cipher (a live
`SerpentCtr`, `SerpentCbc`, `ChaCha20`, `ChaCha20Poly1305`, or
`XChaCha20Poly1305`, for example) currently holds one of the modules, the
corresponding `wipeBuffers()` call throws an ownership error and `stop()`
re-throws it after every other step has run. The Fortuna instance is still
marked disposed and all JavaScript-side key material is still wiped; the
only casualty is the WASM scratch buffer of whichever module threw, which
the caller can clean up by disposing the conflicting cipher.

There is no `start()` or restart capability.

---

## Usage Examples

### Basic usage

The smallest-bundle pair: ChaCha20 generator with SHA-256 hash. No Serpent
WASM is loaded.

```typescript
import { init, Fortuna } from 'leviathan-crypto'
import { ChaCha20Generator } from 'leviathan-crypto/chacha20'
import { SHA256Hash } from 'leviathan-crypto/sha2'
import { chacha20Wasm } from 'leviathan-crypto/chacha20/embedded'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await init({ chacha20: chacha20Wasm, sha2: sha2Wasm })

const rng = await Fortuna.create({ generator: ChaCha20Generator, hash: SHA256Hash })
const key   = rng.get(32)   // for an encryption key
const nonce = rng.get(12)   // for a nonce
rng.stop()
```

### Original Fortuna pair

Serpent-256 with SHA-256 matches the closest analogue to the spec
(swapping AES for Serpent). Use this if your application already pulls in
the Serpent module.

```typescript
import { init, Fortuna } from 'leviathan-crypto'
import { SerpentGenerator } from 'leviathan-crypto/serpent'
import { SHA256Hash } from 'leviathan-crypto/sha2'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await init({ serpent: serpentWasm, sha2: sha2Wasm })

const rng = await Fortuna.create({ generator: SerpentGenerator, hash: SHA256Hash })
const bytes = rng.get(32)
rng.stop()
```

### Modern combination

ChaCha20 with SHA3-256. Both primitives are post-2010 designs; useful when
you want the SHA-3 sponge construction in your CSPRNG accumulator.

```typescript
import { init, Fortuna } from 'leviathan-crypto'
import { ChaCha20Generator } from 'leviathan-crypto/chacha20'
import { SHA3_256Hash } from 'leviathan-crypto/sha3'
import { chacha20Wasm } from 'leviathan-crypto/chacha20/embedded'
import { sha3Wasm } from 'leviathan-crypto/sha3/embedded'

await init({ chacha20: chacha20Wasm, sha3: sha3Wasm })

const rng = await Fortuna.create({ generator: ChaCha20Generator, hash: SHA3_256Hash })
const bytes = rng.get(32)
rng.stop()
```

### Adding custom entropy

```typescript
import { init, Fortuna, utf8ToBytes } from 'leviathan-crypto'
import { SerpentGenerator } from 'leviathan-crypto/serpent'
import { SHA256Hash } from 'leviathan-crypto/sha2'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await init({ serpent: serpentWasm, sha2: sha2Wasm })
const rng = await Fortuna.create({ generator: SerpentGenerator, hash: SHA256Hash })

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
import { ChaCha20Generator } from 'leviathan-crypto/chacha20'
import { SHA256Hash } from 'leviathan-crypto/sha2'
import { chacha20Wasm } from 'leviathan-crypto/chacha20/embedded'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await init({ chacha20: chacha20Wasm, sha2: sha2Wasm })

// Fortuna automatically registers browser event listeners on creation:
//   mousemove (throttled to 50ms), keydown, click, scroll,
//   touchstart, touchmove, touchend,
//   devicemotion, deviceorientation, orientationchange.
// Every user interaction feeds entropy into the pools.
// No manual setup is needed; collection starts immediately.

const rng = await Fortuna.create({ generator: ChaCha20Generator, hash: SHA256Hash })

// The longer the user interacts with the page before you generate,
// the more entropy accumulates. The initial OS seed is strong enough
// for immediate use.
document.querySelector('#generate')?.addEventListener('click', () => {
    const bytes = rng.get(32)
    console.log('Generated:', bytes)
})

// Stop the collectors when the page unloads or the component unmounts.
window.addEventListener('beforeunload', () => rng.stop())
```

### Providing initial entropy at creation

```typescript
import { init, Fortuna } from 'leviathan-crypto'
import { SerpentGenerator } from 'leviathan-crypto/serpent'
import { SHA256Hash } from 'leviathan-crypto/sha2'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await init({ serpent: serpentWasm, sha2: sha2Wasm })

// Pass extra entropy at creation time. It is mixed into the pools during
// initialization, before the generator is first seeded.
const extraSeed = new Uint8Array(64)
crypto.getRandomValues(extraSeed)

const rng = await Fortuna.create({
    generator: SerpentGenerator,
    hash: SHA256Hash,
    entropy: extraSeed,
})
const bytes = rng.get(32)
rng.stop()
```

---

## Error Conditions

| Condition | What happens |
|-----------|-------------|
| `init()` not called for the required modules | `Fortuna.create()` throws: `leviathan-crypto: call init({ <m1>: ..., <m2>: ... }) before using Fortuna`, naming the modules required by the chosen generator and hash. |
| `opts.generator` or `opts.hash` missing | `Fortuna.create()` throws `TypeError: leviathan-crypto: Fortuna.create() requires { generator, hash }`. |
| `hash.outputSize !== generator.keySize` | `Fortuna.create()` throws `RangeError: leviathan-crypto: Fortuna requires hash.outputSize (X) to match generator.keySize (Y)`. |
| No working entropy source | `Fortuna.create()` throws: `leviathan-crypto: Fortuna initialization could not gather sufficient entropy. No working crypto.getRandomValues or node:crypto in this environment.` |
| `new Fortuna()` | Compile-time error. The constructor is private. TypeScript will not allow it. |
| Any method after `stop()` | Throws: `Fortuna instance has been disposed`. The instance is permanently disposed. |

---

## How It Works (Simplified)

For readers who want to understand what Fortuna does internally, without
reading the spec:

1. **Entropy collection.** Background listeners and timers capture small,
   unpredictable measurements (mouse coordinates, nanosecond timings, memory
   usage) and feed them into 32 separate pools via the chosen hash
   function's chaining construction.

2. **Reseed.** When pool 0 has accumulated enough entropy and enough time
   has passed since the last reseed, Fortuna combines the contents of
   eligible pools (per *Practical Cryptography* §9.5.5: pool P_i contributes
   when 2^i divides the reseed counter) into a seed, and derives a new
   generation key: `genKey = hash(genKey || seed)`.

3. **Generation.** To produce output, the generator runs the chosen cipher
   PRF on an incrementing counter under the current generation key. For
   Serpent-256, this is ECB encryption of the counter block. For ChaCha20,
   this is the block function with a fixed zero nonce and the counter as
   block index. The output is the concatenation of cipher output blocks,
   truncated to the requested length.

4. **Key replacement.** Immediately after producing output, the generator
   runs again to produce 32 fresh bytes for the new generation key. The old
   key is wiped. This is what provides forward secrecy.

---

## Coexistence with raw ciphers

`Fortuna` calls into the chosen `Generator` and `HashFn` for every
operation. Both are stateless: they assert that no other instance owns the
WASM module before each call, but they do not acquire the module
themselves.

If you construct a stateful cipher that does acquire the module, subsequent
Fortuna operations on the same module throw the ownership error from
`init.ts`:

```
leviathan-crypto: another stateful instance is using the '<module>' WASM module — call dispose() on it before constructing a new one
```

The relevant pairings:

- `SerpentGenerator` blocked by `Serpent`, `SerpentCtr`, `SerpentCbc`, or any other live serpent acquirer.
- `ChaCha20Generator` blocked by `ChaCha20` (the raw stream cipher acquires the chacha20 module on construction).
- `SHA256Hash` blocked by any future stateful sha2 user (none currently exist; `HMAC_SHA256` and `HKDF_SHA256` are atomic).
- `SHA3_256Hash` blocked by `SHAKE128` or `SHAKE256` while they hold the sha3 module, or by `MlKem*` keypair generation while it holds the sha3 module for its duration.

Disposing the conflicting cipher restores normal operation. `fortuna.stop()`
called while a conflicting cipher still holds the module also throws the
same ownership error, but does so *after* marking the instance disposed and
wiping all JavaScript-side key material. The throw signals only that the
inner WASM module's scratch buffer was not zeroed. The Fortuna instance is
permanently disposed regardless.

The library raises this as an error rather than allowing two instances to
clobber each other's WASM state, which would silently produce incorrect
output from both.

---

## Cross-References

| Document | Description |
| -------- | ----------- |
| [index](./README.md) | Project Documentation index |
| [architecture](./architecture.md) | architecture overview, module relationships, buffer layouts, and build pipeline |
| [serpent](./serpent.md) | Serpent-256 TypeScript API (one option for the Fortuna generator) |
| [chacha20](./chacha20.md) | ChaCha20 TypeScript API (the other option for the Fortuna generator) |
| [sha2](./sha2.md) | SHA-256 TypeScript API (one option for the Fortuna hash) |
| [sha3](./sha3.md) | SHA3-256 TypeScript API (the other option for the Fortuna hash) |
| [types](./types.md) | `Generator` and `HashFn` interface definitions |
| [asm_serpent](./asm_serpent.md) | Serpent-256 WASM implementation details |
| [asm_chacha](./asm_chacha.md) | ChaCha20 WASM implementation details |
| [asm_sha2](./asm_sha2.md) | SHA-256 WASM implementation details |
| [asm_sha3](./asm_sha3.md) | SHA3 WASM implementation details |
| [utils](./utils.md) | `randomBytes()` for simpler random generation needs |
