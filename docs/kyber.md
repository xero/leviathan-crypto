# ML-KEM (Kyber): Post-Quantum Key Encapsulation

> [!NOTE]
> Post-quantum key encapsulation via ML-KEM (FIPS 203), plus `KyberSuite`
> for hybrid KEM + symmetric AEAD with `Seal`, `SealStream`, and `OpenStream`.

> ### Table of Contents
> - [Overview](#overview)
> - [Parameter Sets](#parameter-sets)
> - [Init](#init)
> - [MlKem API](#mlkem-api)
> - [KyberSuite](#kybersuite)
> - [Format enum](#format-enum)
> - [Full example](#full-example)
> - [Error reference](#error-reference)

---

## Overview

ML-KEM (formerly Kyber) is a lattice-based key encapsulation mechanism
standardized by NIST in FIPS 203. It provides key agreement that is secure
against both classical and quantum adversaries.

This module provides three things. `MlKem512`, `MlKem768`, and `MlKem1024`
give you raw KEM operations: keygen, encapsulate, and decapsulate. Use these
when you need direct access to the KEM. `KyberSuite` is a factory that wraps
a `MlKemBase` instance and an inner `CipherSuite` into a hybrid KEM + AEAD
suite. Pass the result to `Seal`, `SealStream`, or `OpenStream` exactly as
you would a symmetric cipher suite. All three parameter sets are verified
against 240 NIST ACVP test vectors covering keygen, encap, decap, and
implicit rejection.

---

## Parameter Sets

| Class | NIST Name | ek size | dk size | ct size | Security |
|-------|-----------|---------|---------|---------|----------|
| `MlKem512` | ML-KEM-512 | 800 B | 1632 B | 768 B | Category 1 |
| `MlKem768` | ML-KEM-768 | 1184 B | 2400 B | 1088 B | Category 3 |
| `MlKem1024` | ML-KEM-1024 | 1568 B | 3168 B | 1568 B | Category 5 |

Use `MlKem768` for general-purpose applications. Use `MlKem512` only if you
have strict size or performance constraints. Use `MlKem1024` for long-lived
keys or high-assurance requirements.

---

## Init

```typescript
import { init } from 'leviathan-crypto'
import { kyberWasm }    from 'leviathan-crypto/kyber/embedded'
import { sha3Wasm }     from 'leviathan-crypto/sha3/embedded'
import { chacha20Wasm } from 'leviathan-crypto/chacha20/embedded'
import { sha2Wasm }     from 'leviathan-crypto/sha2/embedded'

await init({ kyber: kyberWasm, sha3: sha3Wasm, chacha20: chacha20Wasm, sha2: sha2Wasm })
```

Both `kyber` and `sha3` are required. The kyber module handles polynomial
arithmetic. The sha3 module provides the Keccak sponge operations used for
key generation and encapsulation. If using `KyberSuite` with `XChaCha20Cipher`,
also load `chacha20` and `sha2`. With `SerpentCipher`, load `serpent` and `sha2`.

`'keccak'` is an alias for `'sha3'`; same WASM binary, same instance slot.
You can substitute `keccakWasm` and `init({ keccak: keccakWasm })` anywhere
`sha3` is used. See [init.md](./init.md#keccak-alias-for-ml-kem) for details.

For tree-shakeable imports, the `leviathan-crypto/kyber` subpath exports its
own init function:

```typescript
import { kyberInit } from 'leviathan-crypto/kyber'
import { kyberWasm } from 'leviathan-crypto/kyber/embedded'

await kyberInit(kyberWasm)
```

`kyberInit(source)` initializes only the kyber WASM binary. Note that
ML-KEM classes additionally require `sha3` (or `keccak`) — both modules
must be initialized before constructing any `MlKem*` instance.

---

## MlKem API

All three classes share the same interface via `MlKemBase`. Construct the
parameter set you want and call methods on the instance.

```typescript
import { MlKem768 } from 'leviathan-crypto/kyber'

const kem = new MlKem768()
```

### kem.keygen()

Generates a fresh keypair using CSPRNG randomness.

```typescript
const { encapsulationKey, decapsulationKey } = kem.keygen()
// encapsulationKey: Uint8Array — share with senders
// decapsulationKey: Uint8Array — keep secret, never transmit
```

The encapsulation key (`ek`) is the public key. Share it freely. The
decapsulation key (`dk`) is the private key. Store it securely and never
transmit it.

### kem.keygenDerand(d, z)

Deterministic keygen for testing. Both `d` and `z` must be 32 bytes.
Do not use in production. Randomness must come from the CSPRNG.

### kem.encapsulate(ek)

Generates a shared secret and KEM ciphertext. The sender calls this.

```typescript
const { ciphertext, sharedSecret } = kem.encapsulate(encapsulationKey)
// ciphertext:   Uint8Array — send to recipient alongside your message
// sharedSecret: Uint8Array (32 bytes) — derive session keys from this
```

The shared secret is 32 bytes. It is never transmitted. The sender and
recipient independently derive the same value.

> [!IMPORTANT]
> **FIPS 203 compliance.** `encapsulate(ek)` validates `ek` per FIPS 203 §7.2
> before use and throws `RangeError` with message
> `'leviathan-crypto: encapsulation key failed FIPS 203 §7.2 validity check'`
> if validation fails. The length gate also throws `RangeError` on wrong-length
> input, but does not mention §7.2. Callers who want to probe an `ek` without
> triggering an exception can still call the public
> `checkEncapsulationKey(ek) → boolean` method.

### kem.encapsulateDerand(ek, m)

Deterministic encapsulation. `m` is 32 bytes of randomness. KAT and testing
only. Applies the same FIPS 203 §7.2 validation as `encapsulate(ek)`.

### kem.decapsulate(dk, ciphertext)

Recovers the shared secret. The recipient calls this.

```typescript
const sharedSecret = kem.decapsulate(decapsulationKey, ciphertext)
// sharedSecret: Uint8Array (32 bytes)
```

ML-KEM uses implicit rejection. If the ciphertext was tampered with,
`decapsulate` returns a pseudorandom value derived from a secret random string
rather than throwing. This prevents timing attacks on decapsulation failure.
The shared secret simply won't match, causing authentication failure at the
AEAD layer.

> [!IMPORTANT]
> **FIPS 203 compliance and trust model.** `decapsulate(dk, c)` performs two
> distinct checks. First, it validates `dk` per FIPS 203 §7.3 (embedded `H(ek)`
> match and the embedded `ek`'s own §7.2 range check). On failure it throws
> `RangeError` with message
> `'leviathan-crypto: decapsulation key failed FIPS 203 §7.3 validity check'`.
> This is a local-integrity check on key material, not part of the FO transform;
> it is not constant-time with the tampered-ciphertext path and it is not
> intended to be. ML-KEM assumes `dk` is recipient-controlled local storage.
>
> Second, after `dk` validates, the core Decaps algorithm applies FIPS 203's
> Fujisaki-Okamoto transform. A tampered or otherwise invalid ciphertext is
> handled by implicit rejection: the function returns a pseudorandom 32-byte
> shared secret derived from the secret random value `z` and the ciphertext.
> The caller cannot distinguish "valid ciphertext" from "tampered ciphertext"
> by observing the return value — only downstream AEAD authentication will
> fail in the tampered case.
>
> A caller whose threat model includes adversarially-supplied `dk` (for
> example, decapsulation keys loaded from untrusted storage) should probe
> with the boolean `checkDecapsulationKey(dk)` before calling `decapsulate`,
> so the §7.3 outcome is captured in the same branch as other
> input-validation failures. The library does not ship a strict-mode
> decapsulate that routes §7.3 failure through the FO path — the standard
> does not specify one, and doing so would diverge from the reference
> implementations.

### kem.checkEncapsulationKey(ek)

Returns `true` if `ek` is a well-formed encapsulation key per FIPS 203 §7.2.
Checks length, then decodes the polyvec portion via `polyvec_frombytes` and
scans every coefficient against `c < Q = 3329`.

```typescript
if (!kem.checkEncapsulationKey(ek)) throw new Error('invalid ek')
```

### kem.checkDecapsulationKey(dk)

Returns `true` if `dk` is a well-formed decapsulation key per FIPS 203 §7.3.

### kem.dispose()

Wipes the WASM memory buffers. Call when done with the instance. Every public
kyber op (`keygen`, `encapsulate`, `decapsulate`, `checkDecapsulationKey`)
already zeros sha3 scratch before returning, so sha3 linear memory carries no
residue across an op boundary — `dispose()` handles the kyber module's own
buffers.

### Key sizes by parameter set

| | `MlKem512` | `MlKem768` | `MlKem1024` |
|-|-----------|-----------|------------|
| ek | 800 B | 1184 B | 1568 B |
| dk | 1632 B | 2400 B | 3168 B |
| ciphertext | 768 B | 1088 B | 1568 B |
| sharedSecret | 32 B | 32 B | 32 B |

### MlKemLike

Structural interface implemented by `MlKem512`, `MlKem768`, and `MlKem1024`.
Used by `KyberSuite` and `RatchetKeypair.decap()` — pass any `MlKem*` instance
where a `MlKemLike` is expected.

```typescript
interface MlKemLike {
    readonly params: KyberParams;
    encapsulate(ek: Uint8Array): KyberEncapsulation;
    decapsulate(dk: Uint8Array, c: Uint8Array): Uint8Array;
    keygen(): KyberKeyPair;
}
```

---

## KyberSuite

`KyberSuite` combines a `MlKemBase` instance with an inner `CipherSuite`
(`XChaCha20Cipher` or `SerpentCipher`) into a new object that satisfies the
`CipherSuite` interface. Pass it anywhere you would pass a symmetric cipher suite.

```typescript
import { KyberSuite, MlKem768 } from 'leviathan-crypto/kyber'
import { XChaCha20Cipher }      from 'leviathan-crypto/chacha20'

const kem   = new MlKem768()
const suite = KyberSuite(kem, XChaCha20Cipher)
```

### suite.keygen()

Delegates to `kem.keygen()`. Returns `{ encapsulationKey, decapsulationKey }`.

```typescript
const { encapsulationKey: ek, decapsulationKey: dk } = suite.keygen()
```

### One-shot encryption with Seal

The sender encrypts with `ek`. The recipient decrypts with `dk`.

```typescript
import { Seal } from 'leviathan-crypto'

// sender
const blob = Seal.encrypt(suite, ek, plaintext)

// recipient
const pt = Seal.decrypt(suite, dk, blob)
```

The blob wire format is `preamble || ciphertext`. For KEM suites the preamble
includes the KEM ciphertext:

| Param set | Preamble size |
|-----------|--------------|
| ML-KEM-512 + any cipher | 788 bytes |
| ML-KEM-768 + any cipher | 1108 bytes |
| ML-KEM-1024 + any cipher | 1588 bytes |

### Streaming encryption with SealStream and OpenStream

```typescript
import { SealStream, OpenStream } from 'leviathan-crypto'

// sender
const sealer   = new SealStream(suite, ek)
const preamble = sealer.preamble       // 1108 bytes for MlKem768
const ct0      = sealer.push(chunk0)
const ctFinal  = sealer.finalize(lastChunk)

// recipient
const opener  = new OpenStream(suite, dk, preamble)
const pt0     = opener.pull(ct0)
const ptFinal = opener.finalize(ctFinal)
```

### Mix and match

Any combination of parameter set and inner cipher works:

```typescript
import { SerpentCipher } from 'leviathan-crypto/serpent'
import { MlKem1024 }     from 'leviathan-crypto/kyber'

const suite = KyberSuite(new MlKem1024(), SerpentCipher)
// formatEnum: 0x32 (ML-KEM-1024 + Serpent)
// preamble:   20 + 1568 = 1588 bytes
```

### Key management

Generate a keypair once on the recipient side. Distribute `ek` to all senders
and store `dk` securely. The decapsulation key never leaves the recipient.
There is no session concept at this layer. Each `Seal.encrypt` call performs a
fresh encapsulation with fresh randomness. Before trusting a received public
key, validate it with `kem.checkEncapsulationKey(ek)`.

---

## Format enum

`KyberSuite` sets `formatEnum = kemNibble | cipherNibble`. This is encoded
in byte 0 of the 20-byte header (bits 4-6 = KEM, bits 0-3 = cipher):

| Suite | formatEnum |
|-------|-----------|
| MlKem512 + XChaCha20 | `0x11` |
| MlKem512 + Serpent | `0x12` |
| MlKem768 + XChaCha20 | `0x21` |
| MlKem768 + Serpent | `0x22` |
| MlKem1024 + XChaCha20 | `0x31` |
| MlKem1024 + Serpent | `0x32` |

Symmetric suites have KEM bits = `0x00` and are backward compatible.

---

## Full example

```typescript
import { init, Seal }           from 'leviathan-crypto'
import { KyberSuite, MlKem768 } from 'leviathan-crypto/kyber'
import { XChaCha20Cipher }      from 'leviathan-crypto/chacha20'
import { kyberWasm }    from 'leviathan-crypto/kyber/embedded'
import { sha3Wasm }     from 'leviathan-crypto/sha3/embedded'
import { chacha20Wasm } from 'leviathan-crypto/chacha20/embedded'
import { sha2Wasm }     from 'leviathan-crypto/sha2/embedded'

await init({ kyber: kyberWasm, sha3: sha3Wasm, chacha20: chacha20Wasm, sha2: sha2Wasm })

const kem   = new MlKem768()
const suite = KyberSuite(kem, XChaCha20Cipher)

// keygen — once, on the recipient side
const { encapsulationKey: ek, decapsulationKey: dk } = suite.keygen()
// store dk securely; distribute ek to senders

// sender — only needs ek
const message = new TextEncoder().encode('hello post-quantum world')
const blob    = Seal.encrypt(suite, ek, message)

// recipient — only needs dk
const plaintext = Seal.decrypt(suite, dk, blob)
console.log(new TextDecoder().decode(plaintext)) // 'hello post-quantum world'

kem.dispose()
```

---

## Error reference

| Condition | Type | Message |
|-----------|------|---------|
| Constructed before `init({ kyber: ... })` | `Error` | `leviathan-crypto: call init({ kyber: ... }) before using MlKem classes` |
| Constructed before `init({ sha3: ... })` | `Error` | `leviathan-crypto: call init({ sha3: ... }) before using MlKem classes` |
| `encapsulate` with wrong-length ek | `RangeError` | `encapsulation key must be N bytes (got M)` |
| `encapsulate` with ek that fails §7.2 validation | `RangeError` | `leviathan-crypto: encapsulation key failed FIPS 203 §7.2 validity check` |
| `decapsulate` with wrong-length dk | `RangeError` | `decapsulation key must be N bytes (got M)` |
| `decapsulate` with dk that fails §7.3 validation | `RangeError` | `leviathan-crypto: decapsulation key failed FIPS 203 §7.3 validity check` |
| `decapsulate` with wrong-length ciphertext | `RangeError` | `ciphertext must be N bytes (got M)` |
| `keygenDerand` with wrong-length `d` | `RangeError` | `d seed must be 32 bytes (got N)` |
| `keygenDerand` with wrong-length `z` | `RangeError` | `z seed must be 32 bytes (got N)` |
| `encapsulateDerand` with wrong-length `m` | `RangeError` | `randomness m must be 32 bytes (got N)` |
| Another stateful instance holds `kyber` or `sha3` | `Error` | `leviathan-crypto: another stateful instance is using the '…' WASM module — call dispose() on it before constructing a new one` |
| `Seal.decrypt` with ek instead of dk | `RangeError` | `key must be N bytes (got M)` (dk ≠ ek size) |
| `KyberSuite` with unsupported k value | `Error` | `unsupported ML-KEM k=N` |

---


## Cross-References

| Document | Description |
| -------- | ----------- |
| [index](./README.md) | Project Documentation index |
| [architecture](./architecture.md) | architecture overview, module relationships, buffer layouts, and build pipeline |
| [authenticated encryption](./aead.md) | `Seal`, `SealStream`, `OpenStream`: cipher-agnostic AEAD APIs using a `CipherSuite` such as `SerpentCipher` or `XChaCha20Cipher` |
| [ciphersuite](./ciphersuite.md) | `CipherSuite` interface, `SerpentCipher`, `XChaCha20Cipher`, `KyberSuite` |
| [kyber_audit](./kyber_audit.md) | ML-KEM implementation audit |
| [ratchet](./ratchet.md) | `ratchetInit`, `KDFChain`, `kemRatchetEncap`, `kemRatchetDecap`: post-quantum ratchet KDF primitives |
| [ratchet_audit](./ratchet_audit.md) | ratchet KDF implementation audit |
| [init](./init.md) | module initialization and WASM loading |
| [exports](./exports.md) | full export list |

