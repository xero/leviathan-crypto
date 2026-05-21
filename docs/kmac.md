<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### SP 800-185 cSHAKE and KMAC TypeScript API Reference

Covers the two NIST SP 800-185 functions in scope for this library, cSHAKE (customizable SHAKE) and KMAC (the Keccak-based MAC), plus their XOF variants. TupleHash and ParallelHash from the same spec are out of scope. All six classes are built on the SHA-3 module's Keccak sponge; for the WASM internals see [asm_sha3.md](./asm_sha3.md).

> ### Table of Contents
> - [Overview](#overview)
> - [Security Notes](#security-notes)
> - [When to Use cSHAKE vs KMAC vs HMAC](#when-to-use-cshake-vs-kmac-vs-hmac)
> - [Module Init](#module-init)
> - [API Reference](#api-reference)
>   - [CSHAKE128](#cshake128)
>   - [CSHAKE256](#cshake256)
>   - [KMAC128](#kmac128)
>   - [KMAC256](#kmac256)
>   - [KMACXOF128](#kmacxof128)
>   - [KMACXOF256](#kmacxof256)
> - [Usage Examples](#usage-examples)
> - [Error Conditions](#error-conditions)

---

## Overview

NIST SP 800-185 builds four new Keccak-based functions on top of the FIPS 202 SHA-3 standard. This library ships the two that matter for general application code: cSHAKE and KMAC. TupleHash and ParallelHash from the same spec are not implemented.

**cSHAKE** is SHAKE with a customization-string domain separation prefix. The same input under two different customization strings produces independent output streams, so a single Keccak primitive serves many protocol contexts without collision. The spec exposes two parameters: `N` (a NIST-reserved function name) and `S` (the caller's customization string). Per SP 800-185 §3.4, "users of cSHAKE should not make up their own names", so the public API hides `N` and only exposes `S`.

**KMAC** is cSHAKE keyed with a byte-encoded key prefix, plus a right-encoded output-length suffix that binds the output length into the MAC computation. The result is a fixed-output keyed Keccak MAC, with NIST-standard domain separation and a clean constant-time `verify` path.

**KMACXOF** is KMAC in XOF mode. Per SP 800-185 §4.3.1 the right-encoded suffix is `right_encode(0)`, signaling that the output length is caller-driven via `squeeze`. There is no canonical tag length, so KMACXOF classes do not expose a static `verify`.

---

## Security Notes

> [!IMPORTANT]
> Read these before using the API. KMAC and cSHAKE inherit SHAKE's sponge construction, so the SHA-3 security notes apply; the items below are specific to the SP 800-185 surface.

- **Customization is required, no default.** Every cSHAKE constructor takes a customization byte string and rejects the empty case where the spec collapses to plain SHAKE. KMAC and KMACXOF take a customization byte string that may be empty when no domain separation is needed, but a stable, distinct context string at every call site is the right default. A version-tagged ASCII label is a reasonable choice.

- **Empty key throws.** KMAC with an empty key collapses to keyless cSHAKE. The constructor rejects the empty case and directs the caller to `CSHAKE128` or `CSHAKE256` if that is what they wanted.

- **Zero-length output throws (fixed-output KMAC).** KMAC's `right_encode(L*8)` suffix is part of the MAC's input, so `outLen` is bound at construction and must be at least 1 byte. The XOF variants inherit the SHAKE convention: `squeeze(n)` requires `n >= 1`.

- **`verify` throws on mismatch, returns true on success.** This matches the AEAD pattern used throughout leviathan-crypto. The thrown `AuthenticationError` carries a discriminator string of `'kmac128'` or `'kmac256'` depending on the class. KMACXOF variants do not have a `verify` method because the output length is not canonical; squeeze the expected number of bytes and use [`constantTimeEqual`](./utils.md#constanttimeequal) directly.

- **Not formally key-committing.** KMAC binds output to a single key in practice, but is not formally proven to be key-committing. KMAC is appropriate for single-key MAC use and standalone tag verification. Composing it into AEAD-style envelopes where multiple keys could legitimately claim the same tag should use a key-committing construction instead.

- **Call `dispose()` when finished.** Every cSHAKE and KMAC class holds exclusive access to the `sha3` WASM module from construction until disposal. `dispose()` zeroes the Keccak state, the input and output buffers, the metadata slots, and the TS-side block buffer, then releases the exclusivity token. Disposal is idempotent.

---

## When to Use cSHAKE vs KMAC vs HMAC

**Use KMAC** when you want a MAC built on the SHA-3 family, when you want built-in customization-string domain separation, or when you want defense in depth against a future weakness in SHA-2. Pair `KMAC128.verify` or `KMAC256.verify` for constant-time tag checks. Use `KMACXOF128` or `KMACXOF256` for variable-length keyed output: key stretching, deriving multiple keys from one MAC chain, or any case where the receiver squeezes more than one fixed-length value.

**Use cSHAKE** when you want a customized XOF without keying: a domain-separated random oracle, KDF-style output expansion under a context tag, or any case where you want a customizable hash and no key material is in play.

**Use HMAC** when you are already in the SHA-2 ecosystem, when RFC interop matters, when the SHA-3 module is not initialized and adding it costs more than the SHA-3 family's value buys, or when you want a primitive with the longest published analytical history. HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512 are documented in [sha2.md](./sha2.md).

---

## Module Init

All six classes require the `sha3` WASM module. Initialize via the root `init()` or the subpath `sha3Init()`.

### `init({ sha3: sha3Wasm })`

```typescript
import { init, CSHAKE128, KMAC256, KMACXOF128 } from 'leviathan-crypto'
import { sha3Wasm } from 'leviathan-crypto/sha3/embedded'

await init({ sha3: sha3Wasm })

const cs   = new CSHAKE128(new TextEncoder().encode('My Context'))
const mac  = new KMAC256(key, 32, new TextEncoder().encode('My Tag'))
const xof  = new KMACXOF128(key, new TextEncoder().encode('My Stream'))
```

### `sha3Init(sha3Wasm)`

```typescript
import { sha3Init, CSHAKE128 } from 'leviathan-crypto/sha3'
import { sha3Wasm } from 'leviathan-crypto/sha3/embedded'

await sha3Init(sha3Wasm)
const cs = new CSHAKE128(new TextEncoder().encode('My Context'))
```

The `keccak` alias is interchangeable with `sha3`. Same WASM binary, same instance slot. See [init.md](./init.md#keccak-alias-for-ml-kem) for full details.

If you use any cSHAKE or KMAC class without calling `init()` first, the constructor throws.

---

## API Reference

All six classes hold exclusive access to the `sha3` WASM module from construction until `dispose()`. Constructing another `sha3` user while an instance is live throws. Pool workers are unaffected; they instantiate their own modules.

---

### CSHAKE128

Customizable SHAKE128 (SP 800-185 §3). 128-bit security level. Produces variable-length output from a single absorb-then-squeeze pipeline tagged by a non-empty customization string.

```typescript
class CSHAKE128 {
    constructor(customization: Uint8Array)
    hash(msg: Uint8Array, outputLength: number): Uint8Array
    absorb(msg: Uint8Array): this
    squeeze(n: number): Uint8Array
    reset(): this
    dispose(): void
}
```

| Method | Description |
|--------|-------------|
| `hash(msg, outputLength)` | One-shot: reset, absorb, squeeze. Safe on a dirty instance. |
| `absorb(msg)` | Feed data into the sponge. Chainable. Throws if called after `squeeze()`. |
| `squeeze(n)` | Pull `n` bytes of XOF output. Output is contiguous across consecutive squeezes. |
| `reset()` | Re-absorb the cSHAKE prefix and return to a fresh, post-prefix state. Chainable. |
| `dispose()` | Zero all WASM state and release the sha3 exclusivity token. Idempotent. |

`customization` must be non-empty; the empty case is rejected at construction. `outputLength` and `n` must be `>= 1`. After `dispose()`, all methods throw.

```typescript
import { init, CSHAKE128, bytesToHex, utf8ToBytes } from 'leviathan-crypto'
import { sha3Wasm } from 'leviathan-crypto/sha3/embedded'

await init({ sha3: sha3Wasm })

const cs = new CSHAKE128(utf8ToBytes('Email Signature'))
const digest = cs.hash(message, 32)
console.log(bytesToHex(digest))
cs.dispose()
```

---

### CSHAKE256

Customizable SHAKE256 (SP 800-185 §3). 256-bit security level. Same API shape as `CSHAKE128`; only the underlying sponge rate and security strength differ.

```typescript
class CSHAKE256 {
    constructor(customization: Uint8Array)
    hash(msg: Uint8Array, outputLength: number): Uint8Array
    absorb(msg: Uint8Array): this
    squeeze(n: number): Uint8Array
    reset(): this
    dispose(): void
}
```

Method table matches `CSHAKE128` above. `customization` must be non-empty; `outputLength` and `n` must be `>= 1`. After `dispose()`, all methods throw.

```typescript
import { init, CSHAKE256, utf8ToBytes } from 'leviathan-crypto'
import { sha3Wasm } from 'leviathan-crypto/sha3/embedded'

await init({ sha3: sha3Wasm })

const cs = new CSHAKE256(utf8ToBytes('My Application'))
const output = cs.hash(message, 64)
cs.dispose()
```

---

### KMAC128

Keyed Keccak MAC, fixed-output (SP 800-185 §4). 128-bit security level. The output length is bound at construction because the spec's `right_encode(L)` suffix is a function of `L`.

```typescript
class KMAC128 {
    constructor(key: Uint8Array, outLen: number, customization: Uint8Array)
    update(chunk: Uint8Array): this
    finalize(): Uint8Array
    mac(msg: Uint8Array): Uint8Array
    dispose(): void
    static verify(tag: Uint8Array, key: Uint8Array, msg: Uint8Array, customization: Uint8Array): true
}
```

| Method | Description |
|--------|-------------|
| `update(chunk)` | Absorb a chunk of the message. Chainable. Throws after `finalize()`. |
| `finalize()` | Apply `right_encode(outLen*8)`, pad, squeeze `outLen` bytes. Single-use per instance. |
| `mac(msg)` | One-shot equivalent to `update(msg).finalize()`. |
| `dispose()` | Zero all WASM state and release the sha3 exclusivity token. Idempotent. |
| `static verify(tag, key, msg, customization)` | Recompute the MAC and constant-time-compare against `tag`. Returns `true` on match; throws `AuthenticationError('kmac128')` on mismatch. Acquires and releases the `sha3` module around the compute; do not call while another `sha3` user is live. |

`key` must be non-empty. `outLen` must be a positive integer. `customization` may be empty if no domain separation is needed; the encoded prefix is still well-formed.

```typescript
import { init, KMAC128, AuthenticationError, utf8ToBytes } from 'leviathan-crypto'
import { sha3Wasm } from 'leviathan-crypto/sha3/embedded'

await init({ sha3: sha3Wasm })

const cust = utf8ToBytes('My Tag')
const m    = new KMAC128(key, 32, cust)
const tag  = m.mac(message)
m.dispose()

try {
    KMAC128.verify(tag, key, message, cust)
    // tag is valid; proceed
} catch (e) {
    if (e instanceof AuthenticationError) {
        // discriminator: 'kmac128'
    }
}
```

---

### KMAC256

Keyed Keccak MAC, fixed-output, 256-bit security level (SP 800-185 §4). Same API shape as `KMAC128`. The thrown discriminator on a wrong tag is `'kmac256'`.

```typescript
class KMAC256 {
    constructor(key: Uint8Array, outLen: number, customization: Uint8Array)
    update(chunk: Uint8Array): this
    finalize(): Uint8Array
    mac(msg: Uint8Array): Uint8Array
    dispose(): void
    static verify(tag: Uint8Array, key: Uint8Array, msg: Uint8Array, customization: Uint8Array): true
}
```

Method table and constraints match `KMAC128` above. KMAC256 uses the SHA3-256 sponge rate (smaller block, larger capacity) and is appropriate when 256-bit security strength is required.

```typescript
import { init, KMAC256, utf8ToBytes } from 'leviathan-crypto'
import { sha3Wasm } from 'leviathan-crypto/sha3/embedded'

await init({ sha3: sha3Wasm })

const m = new KMAC256(key, 64, utf8ToBytes('My Tag'))
m.update(part1)
m.update(part2)
const tag = m.finalize()
m.dispose()
```

---

### KMACXOF128

XOF variant of KMAC128 (SP 800-185 §4.3.1). Output length is caller-chosen via `squeeze`. The spec's `right_encode(0)` suffix marks the XOF mode.

```typescript
class KMACXOF128 {
    constructor(key: Uint8Array, customization: Uint8Array)
    update(chunk: Uint8Array): this
    squeeze(n: number): Uint8Array
    mac(msg: Uint8Array, outLen: number): Uint8Array
    dispose(): void
}
```

| Method | Description |
|--------|-------------|
| `update(chunk)` | Absorb a chunk of the message. Chainable. Throws if called after `squeeze()`. |
| `squeeze(n)` | Pull `n` bytes of XOF output. Output is contiguous across consecutive squeezes. |
| `mac(msg, outLen)` | One-shot equivalent to `update(msg).squeeze(outLen)`. |
| `dispose()` | Zero all WASM state and the TS-side block buffer, release the sha3 exclusivity token. Idempotent. |

`key` must be non-empty. `n` must be `>= 1`. `customization` may be empty.

There is no `static verify` because no canonical tag length exists. To verify a fixed-length XOF output, squeeze the expected number of bytes and compare with [`constantTimeEqual`](./utils.md#constanttimeequal).

```typescript
import { init, KMACXOF128, utf8ToBytes } from 'leviathan-crypto'
import { sha3Wasm } from 'leviathan-crypto/sha3/embedded'

await init({ sha3: sha3Wasm })

const xof = new KMACXOF128(key, utf8ToBytes('Stream Tag'))
xof.update(message)
const part1 = xof.squeeze(32)
const part2 = xof.squeeze(32)   // continues the same XOF stream
xof.dispose()
```

---

### KMACXOF256

XOF variant of KMAC256 (SP 800-185 §4.3.1). Same API shape as `KMACXOF128` at 256-bit strength.

```typescript
class KMACXOF256 {
    constructor(key: Uint8Array, customization: Uint8Array)
    update(chunk: Uint8Array): this
    squeeze(n: number): Uint8Array
    mac(msg: Uint8Array, outLen: number): Uint8Array
    dispose(): void
}
```

Method table and constraints match `KMACXOF128` above.

```typescript
import { init, KMACXOF256, utf8ToBytes } from 'leviathan-crypto'
import { sha3Wasm } from 'leviathan-crypto/sha3/embedded'

await init({ sha3: sha3Wasm })

const xof = new KMACXOF256(key, utf8ToBytes('Derive'))
const stream = xof.mac(message, 128)
xof.dispose()
```

---

## Usage Examples

### Example 1: One-shot KMAC256

The most common pattern: construct, call `mac()`, dispose.

```typescript
import { init, KMAC256, bytesToHex, utf8ToBytes } from 'leviathan-crypto'
import { sha3Wasm } from 'leviathan-crypto/sha3/embedded'

await init({ sha3: sha3Wasm })

const cust = utf8ToBytes('My Application v1')
const m    = new KMAC256(key, 32, cust)
const tag  = m.mac(message)
m.dispose()

console.log(bytesToHex(tag))
```

---

### Example 2: Streaming KMAC256

When the message arrives in chunks (a network stream, a file read, a protocol-framed payload), call `update()` for each chunk and `finalize()` at the end. The streaming result is identical to the one-shot equivalent.

```typescript
import { init, KMAC256, utf8ToBytes } from 'leviathan-crypto'
import { sha3Wasm } from 'leviathan-crypto/sha3/embedded'

await init({ sha3: sha3Wasm })

const m = new KMAC256(key, 32, utf8ToBytes('My Tag'))
for (const chunk of chunks) {
    m.update(chunk)
}
const tag = m.finalize()
m.dispose()
```

---

### Example 3: KMACXOF256 for key derivation

KMACXOF squeezes caller-driven output. Use it when one MAC chain produces several derived values, or when the receiver picks the output length at runtime.

```typescript
import { init, KMACXOF256, utf8ToBytes } from 'leviathan-crypto'
import { sha3Wasm } from 'leviathan-crypto/sha3/embedded'

await init({ sha3: sha3Wasm })

const xof = new KMACXOF256(key, utf8ToBytes('Subkeys'))
const derived = xof.mac(context, 96)
const encKey  = derived.subarray(0, 32)
const macKey  = derived.subarray(32, 64)
const nonce   = derived.subarray(64, 76)
xof.dispose()
```

---

### Example 4: KMAC256.verify happy path

`verify` returns `true` on match and throws `AuthenticationError` on mismatch. The discriminator is `'kmac256'` for `KMAC256` and `'kmac128'` for `KMAC128`.

```typescript
import { init, KMAC256, AuthenticationError, utf8ToBytes } from 'leviathan-crypto'
import { sha3Wasm } from 'leviathan-crypto/sha3/embedded'

await init({ sha3: sha3Wasm })

const cust = utf8ToBytes('My Tag')
try {
    KMAC256.verify(receivedTag, key, message, cust)
    // tag is valid; proceed
} catch (e) {
    if (e instanceof AuthenticationError) {
        // wrong key, wrong message, wrong customization, or tampered tag
    } else {
        throw e
    }
}
```

---

## Error Conditions

### `sha3` module not initialized

Constructing any cSHAKE or KMAC class before initializing the module throws immediately:

```
Error: leviathan-crypto: call init({ sha3: ... }) before using this class
```

**Fix.** Call `await init({ sha3: sha3Wasm })` once at startup, before constructing any cSHAKE, KMAC, or KMACXOF instance.

---

### Empty customization (cSHAKE only)

`CSHAKE128` and `CSHAKE256` require non-empty customization. Per SP 800-185 §3.3, cSHAKE with both `N` and `S` empty collapses to plain SHAKE. The public API hides `N`, so the empty-customization case becomes "use SHAKE instead":

```
Error: CSHAKE128: customization is empty, use SHAKE128 instead
Error: CSHAKE256: customization is empty, use SHAKE256 instead
```

**Fix.** Pass a non-empty `Uint8Array` for `customization`. If you do not need domain separation, use `SHAKE128` or `SHAKE256` directly from [sha3.md](./sha3.md).

---

### Empty key (KMAC only)

`KMAC128`, `KMAC256`, `KMACXOF128`, and `KMACXOF256` all require a non-empty key. A keyless KMAC degenerates to keyless cSHAKE; the constructor rejects the empty case and points to the corresponding cSHAKE class:

```
Error: KMAC128: empty key, use CSHAKE128 instead
Error: KMAC256: empty key, use CSHAKE256 instead
Error: KMACXOF128: empty key, use CSHAKE128 instead
Error: KMACXOF256: empty key, use CSHAKE256 instead
```

**Fix.** Provide a non-empty key, or use the corresponding `CSHAKE` class if you intended a keyless construction.

---

### Output length out of range

Fixed-output `KMAC128` and `KMAC256` require a positive integer `outLen` at construction. cSHAKE and KMACXOF require `n >= 1` for each `squeeze()`. `CSHAKE.hash` requires `outputLength >= 1`. Violations throw `RangeError`:

```
RangeError: KMAC128: outLen must be a positive integer (got 0)
RangeError: squeeze length must be >= 1 (got 0)
RangeError: outputLength must be >= 1 (got 0)
```

**Fix.** Request at least 1 byte. For variable-length output use the `KMACXOF` or `CSHAKE` classes and squeeze as much as you need.

---

### Update after finalize (fixed-output KMAC)

After `finalize()` returns, the instance is single-use. A second `update()` or `finalize()` throws. Construct a new instance for a fresh MAC.

```
Error: KMAC128: cannot update after finalize
Error: KMAC128: already finalized
```

---

### Update after squeeze (cSHAKE / KMACXOF)

cSHAKE and KMACXOF classes transition from absorb to squeeze on the first `squeeze()` call. Subsequent `absorb()` (cSHAKE) or `update()` (KMACXOF) throws.

```
Error: CSHAKE128: cannot absorb after squeeze, call reset() first
Error: KMACXOF128: cannot update after squeeze
```

**Fix.** For cSHAKE, call `reset()` to return to a fresh post-prefix state. KMACXOF has no `reset()`; construct a new instance to start a fresh stream.

---

### Post-dispose method calls

After `dispose()`, every instance method throws. Disposal is permanent.

```
Error: CSHAKE128: instance has been disposed
Error: KMAC128: instance has been disposed
Error: KMACXOF128: instance has been disposed
```

**Fix.** Construct a new instance to continue.

---

### `AuthenticationError` from `KMAC*.verify`

`KMAC128.verify` and `KMAC256.verify` throw `AuthenticationError` on tag mismatch and return `true` on match. The error carries a discriminator string identifying the source:

| Class | Discriminator |
|-------|---------------|
| `KMAC128.verify` | `'kmac128'` |
| `KMAC256.verify` | `'kmac256'` |

A wrong key, wrong message, wrong customization, or tampered tag all produce the same error. The comparison is constant-time via [`constantTimeEqual`](./utils.md#constanttimeequal), so no information about which bytes differed is leaked. KMACXOF classes have no `static verify` because the output length is not canonical.

---

## Cross-References

| Document | Description |
| -------- | ----------- |
| [index](./README.md) | Project Documentation index |
| [sha3](./sha3.md) | SHA-3 hash functions (SHA3-224 through SHA3-512) and SHAKE128/256 |
| [asm_sha3](./asm_sha3.md) | SHA-3 WASM internals and the SP 800-185 AS exports |
| [architecture](./architecture.md) | Repository structure, build and CI, WASM modules, public API, test suite, and security posture |
| [utils](./utils.md) | `constantTimeEqual` for fixed-length XOF tag verification |
