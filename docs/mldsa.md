<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### ML-DSA (Dilithium): Post-Quantum Digital Signatures

Post-quantum digital signatures via ML-DSA (FIPS 204), the NIST-standardized
module-lattice signature scheme.

> ### Table of Contents
> - [Overview](#overview)
> - [Parameter Sets](#parameter-sets)
> - [Init](#init)
> - [MlDsa API](#mldsa-api)
> - [HashML-DSA (Pre-Hash Variant)](#hashml-dsa-pre-hash-variant)
> - [Validation Behavior](#validation-behavior)
> - [Key & Signature Format](#key--signature-format)
> - [Wipe Discipline](#wipe-discipline)
> - [Error Reference](#error-reference)

---

## Overview

ML-DSA (Module-Lattice-Based Digital Signature Algorithm) is a lattice-based
signature scheme standardized by NIST in FIPS 204. It is the post-quantum
counterpart to RSA and ECDSA: existential unforgeability under chosen-message
attack (EUF-CMA) holds even against adversaries with quantum computers. The
hardness assumption is Module-Learning-With-Errors (M-LWE).

This module exposes three classes, `MlDsa44`, `MlDsa65`, and `MlDsa87`,
covering the three FIPS 204 parameter sets. Each class supports both pure
ML-DSA (FIPS 204 §5.2 / §5.3) and HashML-DSA (FIPS 204 §5.4, pre-hash
variant) across the three signing modes (hedged / deterministic /
externally-randomised) plus their HashML-DSA counterparts.

Verification against the full NIST ACVP corpora, 75 keyGen-FIPS204 vectors
(25 per parameter set), 90 sigGen-FIPS204 external/pure tests, and 45
sigVer-FIPS204 external/pure tests including known-fail cases, confirms
byte-identical pk/sk/σ output and the SUF-CMA-critical malformed-input
checks (FIPS 204 §D.3 / Algorithm 21).

---

## Parameter Sets

| Class      | NIST Name | k | ℓ | η | τ  | λ   | γ₁     | γ₂        | ω  | pk B | sk B  | sig B | Security    |
|------------|-----------|---|---|---|----|-----|--------|-----------|----|------|-------|-------|-------------|
| `MlDsa44`  | ML-DSA-44 | 4 | 4 | 2 | 39 | 128 | 2¹⁷    | (q−1)/88  | 80 | 1312 | 2560  | 2420  | Category 2  |
| `MlDsa65`  | ML-DSA-65 | 6 | 5 | 4 | 49 | 192 | 2¹⁹    | (q−1)/32  | 55 | 1952 | 4032  | 3309  | Category 3  |
| `MlDsa87`  | ML-DSA-87 | 8 | 7 | 2 | 60 | 256 | 2¹⁹    | (q−1)/32  | 75 | 2592 | 4896  | 4627  | Category 5  |

Use `MlDsa65` for general-purpose applications. Use `MlDsa44` only if you
have strict size or performance constraints. Use `MlDsa87` for long-lived
keys or high-assurance requirements.

Sizes are byte-exact. Seed (ξ) is always 32 bytes regardless of parameter set.

---

## Init

```typescript
import { init }       from 'leviathan-crypto'
import { mldsaWasm }  from 'leviathan-crypto/mldsa/embedded'
import { sha3Wasm }   from 'leviathan-crypto/sha3/embedded'

await init({ mldsa: mldsaWasm, sha3: sha3Wasm })
```

Both `mldsa` and `sha3` are required. The mldsa module handles polynomial
arithmetic, NTT, encoding, sampling, and rounding. The sha3 module provides
the Keccak sponge for SHAKE128 (matrix expansion) and SHAKE256 (noise
expansion, key digest, and signing-time hashes).

`'keccak'` is an alias for `'sha3'`; same WASM binary, same instance slot.

For tree-shakeable imports the `leviathan-crypto/mldsa` subpath exports its
own init function:

```typescript
import { mldsaInit } from 'leviathan-crypto/mldsa'
import { mldsaWasm } from 'leviathan-crypto/mldsa/embedded'

await mldsaInit(mldsaWasm)
```

`mldsaInit(source)` initializes only the mldsa WASM binary. Note that
ML-DSA classes additionally require `sha3`, both modules must be
initialized before constructing any `MlDsa*` instance. HashML-DSA with a
SHA-2 family pre-hash (`'SHA2-224'`, `'SHA2-256'`, etc.) additionally
requires `sha2`.

ML-DSA requires WebAssembly SIMD. `init()` throws a clear error on runtimes
without SIMD support. Every major browser and runtime since 2021 supports it.

---

## MlDsa API

All three classes share the same surface, defined by the `MlDsaBase` parent.
Construction is parameter-less, the parameter set is fixed by the class.

### Constructor

```typescript
new MlDsa44()
new MlDsa65()
new MlDsa87()
```

Throws if `init({ mldsa, sha3 })` has not been called. Cheap, runs a
layout assertion on the WASM byte buffers and returns.

### `keygen(): MlDsaKeyPair`

Generate a new key pair using a fresh 32-byte seed from `crypto.getRandomValues`.
Equivalent to calling `keygenDerand` with a random ξ; the local seed buffer is
wiped on return.

```typescript
const dsa = new MlDsa65()
const { verificationKey, signingKey } = dsa.keygen()
// verificationKey: 1952-byte pk (FIPS 204 Algorithm 22 pkEncode)
// signingKey:      4032-byte sk (FIPS 204 Algorithm 24 skEncode)
dsa.dispose()
```

### `keygenDerand(xi: Uint8Array): MlDsaKeyPair`

Deterministic key generation, FIPS 204 §6.1 Algorithm 6. Use this when you
must derive a key from a known seed (testing, ACVP, key escrow, deterministic
deployments). Throws `RangeError` if `xi.length !== 32`.

```typescript
const xi = new Uint8Array(32)
crypto.getRandomValues(xi)

const dsa = new MlDsa65()
const { verificationKey, signingKey } = dsa.keygenDerand(xi)
dsa.dispose()
xi.fill(0)  // ξ is the master secret, wipe after use
```

### `sign(sk, M, ctx?): Uint8Array`

Hedged signing, FIPS 204 §3.4 (recommended default). Produces a signature
of `params.sigBytes` bytes. Each call sources a fresh 32-byte rnd from
`crypto.getRandomValues`, mixes it into the per-signature ρ'', and wipes
the local rnd buffer on return. Two `sign()` calls over the same `(sk, M)`
return different bytes, both verify.

```typescript
const dsa = new MlDsa65()
const { verificationKey, signingKey } = dsa.keygen()
const sig = dsa.sign(signingKey, message)
const ok  = dsa.verify(verificationKey, message, sig)   // true
dsa.dispose()
```

Hedged signing is preferred over deterministic per FIPS 204 §3.4: hedged
signatures remain unforgeable against fault attacks that bias the
rejection-sampling stream, where deterministic signatures do not.

`ctx` defaults to an empty Uint8Array. Caller-supplied ctx must be ≤ 255
bytes per FIPS 204 §5.2 line 1; longer values throw `RangeError`. The
signature binds (M, ctx), verifying with a different ctx returns false.

### `signDeterministic(sk, M, ctx?): Uint8Array`

Deterministic signing, FIPS 204 §3.4. Sets rnd ← 0³² so two signatures
over the same `(sk, M, ctx)` return identical bytes.

```typescript
const sig1 = dsa.signDeterministic(signingKey, message)
const sig2 = dsa.signDeterministic(signingKey, message)
// sig1 === sig2 byte-for-byte
```

⚠ Deterministic signatures are vulnerable to fault attacks per FIPS 204
§3.4. Use only when no entropy source is available (embedded boot,
hard reproducibility requirement) or when running CAVP / ACVP tests.
Prefer `sign()` for production.

### `signDerand(sk, M, ctx, rnd): Uint8Array`

Externally-randomised signing, testing / CAVP API. Caller supplies a
32-byte `rnd`; the library does not mix in additional entropy.

```typescript
const rnd = randomBytes(32)
const sig = dsa.signDerand(signingKey, message, ctx, rnd)
```

⚠ Hard contract on the caller: `rnd` MUST come from an approved RBG
(FIPS 204 §3.6.1) and MUST NOT be reused across signatures. Reuse leaks
the signing key. The library does not enforce single-use; the caller
owns this discipline.

### `verify(vk, M, sig, ctx?): boolean`

Pure ML-DSA verify, FIPS 204 §5.3 Algorithm 3 / §6.3 Algorithm 8.
Returns `true` only if both the FIPS 204 norm bound (‖z‖∞ < γ₁ − β) holds
and the constant-time comparison of c̃ to the recomputed c̃' succeeds.

```typescript
const ok = dsa.verify(verificationKey, message, sig, ctx)   // boolean
```

`verify` returns `false` on a wrong signature, throws `RangeError` on a
caller-side contract violation. See [Validation Behavior](#validation-behavior)
for the exact split.

### `signHash(sk, M, ph, ctx?): Uint8Array`

Hedged HashML-DSA sign, FIPS 204 §5.4 Algorithm 4. Pre-hashes `M` with the
caller-selected approved function `ph`, builds
`M' = 0x01 ‖ |ctx| ‖ ctx ‖ OID(ph) ‖ PH_M`, and drives ML-DSA.Sign_internal
with a fresh 32-byte rnd (same hedged-vs-deterministic rationale as
[`sign`](#signsk-m-ctx-uint8array)).

```typescript
import { MlDsa65 } from 'leviathan-crypto'

const dsa = new MlDsa65()
const { signingKey, verificationKey } = dsa.keygen()
const sig = dsa.signHash(signingKey, message, 'SHA2-256')
const ok  = dsa.verifyHash(verificationKey, message, sig, 'SHA2-256')
dsa.dispose()
```

`ph` is required and immediately follows the bytes it operates on (`M`
for sign, `sig` for verify). The 12 approved §5.4.1 choices have no
cryptographic priority, so callers must select one explicitly, there is
no default. `ctx` trails as an optional parameter so the common-case
empty-ctx call reads cleanly. See
[Pre-Hash Algorithms](#pre-hash-algorithms) for the full list and module
dependencies.

### `signHashDeterministic(sk, M, ph, ctx?): Uint8Array`

Deterministic HashML-DSA sign, FIPS 204 §5.4 Algorithm 4 with `rnd ← 0³²`.
Same fault-attack caveat as
[`signDeterministic`](#signdeterministicsk-m-ctx-uint8array).

### `signHashDerand(sk, M, ph, ctx, rnd): Uint8Array`

Externally-randomised HashML-DSA sign, testing / CAVP API. Caller supplies
the 32-byte rnd; same contract as
[`signDerand`](#signderandsk-m-ctx-rnd-uint8array). Used to oracle ACVP
HashML-DSA sigGen vectors with byte-identical output.

### `verifyHash(vk, M, sig, ph, ctx?): boolean`

HashML-DSA verify, FIPS 204 §5.4 Algorithm 5. Same return / throw posture
as [`verify`](#verifyvk-m-sig-ctx-boolean): `false` on any signature
failure (wrong sig, malformed hint, length mismatch on `vk` / `sig`),
`RangeError` only on caller-side contract violations such as
`ctx.length > 255` or unsupported `ph`.

> [!CAUTION]
> **Pure-ML-DSA and HashML-DSA signatures are not interchangeable** even
> on the same key, because the M' construction binds a different
> domain-sep byte (FIPS 204 §3.6.4). A signature produced by `sign` will
> NOT verify under `verifyHash` and vice versa. Treat the two as
> separate signature schemes that happen to share a key format.

### `signHashPrehashed(sk, digest, ph, ctx?): Uint8Array`

Hedged HashML-DSA sign with a caller-supplied prehash, FIPS 204 §5.4
Algorithm 4 lines 22-24 (the post-PH path). Skips step 1 (`PH ← Hash(M,
ph)`) and uses `digest` directly. Identical Sign_internal output to
[`signHash`](#signhashsk-m-ph-ctx-uint8array) when `digest = Hash(M, ph)`.

`digest` must be exactly the FIPS 204 §5.4.1 output length for `ph`: 28
bytes for `SHA2-224` / `SHA2-512/224` / `SHA3-224`, 32 bytes for
`SHA2-256` / `SHA2-512/256` / `SHA3-256` / `SHAKE128`, 48 bytes for
`SHA2-384` / `SHA3-384`, 64 bytes for `SHA2-512` / `SHA3-512` /
`SHAKE256`. A mismatch throws
[`SigningError('sig-malformed-input')`](#error-reference). The caller
owns `digest` and is responsible for wiping it; the method never mutates
the buffer.

Use this entry point when:

- The transcript already produced the digest as part of a protocol step
  (e.g. a signed-blob commit where the digest is the canonical identifier).
- The signer cannot buffer `M` into a single `Uint8Array` (a `SignStream`-
  style API computes the prehash incrementally and hands `signHashPrehashed`
  the finalized digest).
- A FIPS 140 boundary places the digest computation in a different module
  from ML-DSA, FIPS 204 §5.4 explicitly endorses the split.

Hedged is the default per FIPS 204 §3.4; see
[`sign`](#signsk-m-ctx-uint8array) for the rationale.

### `signHashPrehashedDeterministic(sk, digest, ph, ctx?): Uint8Array`

Deterministic prehashed sign, `rnd ← 0³²` per FIPS 204 §3.4. Same
fault-attack caveat as
[`signDeterministic`](#signdeterministicsk-m-ctx-uint8array). Produces
byte-identical output to
[`signHashDeterministic`](#signhashdeterministicsk-m-ph-ctx-uint8array)
when `digest = Hash(M, ph)`.

### `signHashPrehashedDerand(sk, digest, ph, rnd, ctx?): Uint8Array`

Externally-randomised prehashed sign, testing / CAVP API. Caller
supplies the 32-byte `rnd` (FIPS 204 §3.4 contract: `rnd` MUST come from
an approved RBG and MUST NOT be reused across signatures). Used to
re-oracle ACVP HashML-DSA sigGen vectors through the prehashed entry
point with byte-identical output.

### `verifyHashPrehashed(vk, digest, sig, ph, ctx?): boolean`

HashML-DSA verify with a caller-supplied prehash, FIPS 204 §5.4
Algorithm 5 lines 17-19 (the post-PH path). Same return / throw posture
as [`verifyHash`](#verifyhashvk-m-sig-ph-ctx-boolean): returns boolean
for every signature outcome; throws `RangeError` only on caller-side
contract violations (`ctx.length > 255`, unsupported `ph`).

Wrong-size `digest` is a structural mismatch (a different-shaped M'
than the signer would have produced) and returns `false`, mirroring
how wrong-length `vk` / `sig` already return `false` per FIPS 204
§3.6.2. This DIVERGES from the sign-side behaviour, which throws
`SigningError` on wrong-size `digest`: on the sign side the caller
fed bad input (a contract violation); on the verify side, "this is
not a valid signature" is the correct verdict.

> [!CAUTION]
> The prehashed family signs `digest` *as if* it were `Hash(M, ph)`,
> the library cannot check whether `digest` actually equals that hash.
> A protocol that wants to bind a specific `M` MUST compute the digest
> itself (or verify the digest's provenance) before calling these
> methods; otherwise an attacker that controls `digest` can produce a
> signature that is consistent with any pre-image they later choose.

### `dispose(): void`

Wipe all mldsa WASM scratch memory. Idempotent. Safe to call multiple times.
Does not wipe sha3 / sha2 scratch, every public op already does that under
its own exclusivity guard before returning.

### Field: `params: MlDsaParams`

Read-only parameter-set constants:

```typescript
interface MlDsaParams {
    paramSet: 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87'
    k:        number   // matrix rows
    l:        number   // matrix cols (ℓ)
    eta:      number   // noise parameter (η)
    tau:      number   // # of ±1 in challenge polynomial (τ)
    lambda:   number   // collision strength in bits (λ)
    gamma1:   number   // y coefficient range (mask)
    gamma2:   number   // low-order rounding modulus
    omega:    number   // max # of 1s in hint
    beta:     number   // = τ · η
    pkBytes:  number
    skBytes:  number
    sigBytes: number
}
```

---

## HashML-DSA (Pre-Hash Variant)

HashML-DSA, FIPS 204 §5.4, wraps the same ML-DSA Sign_internal /
Verify_internal primitives pure ML-DSA uses, but pre-hashes the message
with a caller-selected approved function and prefixes M' with the
function's OID DER bytes plus a different domain-sep byte. The four
public methods [`signHash`](#signhashsk-m-ph-ctx-uint8array),
[`signHashDeterministic`](#signhashdeterministicsk-m-ph-ctx-uint8array),
[`signHashDerand`](#signhashderandsk-m-ph-ctx-rnd-uint8array), and
[`verifyHash`](#verifyhashvk-m-sig-ph-ctx-boolean) match the shape of
their pure counterparts with `ph: PreHashAlgorithm` placed immediately
after the message bytes (or signature, for verify).

Four parallel prehashed-input variants
([`signHashPrehashed`](#signhashprehashedsk-digest-ph-ctx-uint8array),
[`signHashPrehashedDeterministic`](#signhashprehasheddeterministicsk-digest-ph-ctx-uint8array),
[`signHashPrehashedDerand`](#signhashprehashedderandsk-digest-ph-rnd-ctx-uint8array),
and
[`verifyHashPrehashed`](#verifyhashprehashedvk-digest-sig-ph-ctx-boolean))
skip the internal `PH ← Hash(M, ph)` step and accept the digest from
the caller. Use these when the digest already exists (a streaming
signer that absorbed `M` incrementally, a transcript that carries the
digest as its identifier, or a FIPS 140 boundary that computes the
hash in a separate module). When `digest = Hash(M, ph)`, the prehashed
and non-prehashed forms produce byte-identical signatures.

Use HashML-DSA when:

- The caller cannot stream the full message into a single `Uint8Array`
  before signing (a hash digest is constant-size).
- A protocol identifier prescribes a specific pre-hash function (e.g.
  X.509 CMS / S/MIME signature suites identifying the digest by OID).
- A FIPS 140 boundary forces the digest computation into a different
  cryptographic module from ML-DSA itself, FIPS 204 §5.4 explicitly
  permits this.

Use pure ML-DSA otherwise: it offers a larger collision-resistance margin
than any pre-hash function except SHA-512 / SHAKE256, and elides one
hashing pass.

### Pre-Hash Algorithms

The 12 approved pre-hash functions (FIPS 204 §5.4.1) and the OID DER
trailing arc on the shared 2.16.840.1.101.3.4.2.x branch:

| `PreHashAlgorithm`  | OID arc | Output bytes | Required init |
| ------------------- | ------- | ------------ | ------------------------- |
| `'SHA2-224'`        | .04     | 28           | `init({ mldsa, sha3, sha2 })` |
| `'SHA2-256'`        | .01     | 32           | `init({ mldsa, sha3, sha2 })` |
| `'SHA2-384'`        | .02     | 48           | `init({ mldsa, sha3, sha2 })` |
| `'SHA2-512'`        | .03     | 64           | `init({ mldsa, sha3, sha2 })` |
| `'SHA2-512/224'`    | .05     | 28           | `init({ mldsa, sha3, sha2 })` |
| `'SHA2-512/256'`    | .06     | 32           | `init({ mldsa, sha3, sha2 })` |
| `'SHA3-224'`        | .07     | 28           | `init({ mldsa, sha3 })` |
| `'SHA3-256'`        | .08     | 32           | `init({ mldsa, sha3 })` |
| `'SHA3-384'`        | .09     | 48           | `init({ mldsa, sha3 })` |
| `'SHA3-512'`        | .0A     | 64           | `init({ mldsa, sha3 })` |
| `'SHAKE128'`        | .0B     | 32 (256-bit) | `init({ mldsa, sha3 })` |
| `'SHAKE256'`        | .0C     | 64 (512-bit) | `init({ mldsa, sha3 })` |

The leviathan-crypto `init({ ... })` cache validates `sha2` only when
the caller actually uses a SHA-2 family pre-hash. Pure ML-DSA usage and
SHA3-* / SHAKE-prehash HashML-DSA usage need only `init({ mldsa, sha3 })`.

OID DER prefix: every entry is the 11-byte sequence
`06 09 60 86 48 01 65 03 04 02 NN`, the first 10 bytes are
`OBJECT IDENTIFIER (length 9) ‖ joint-iso-itu-t.country.us.organization
.gov.csor.nistalgorithm.hashalgs`, and `NN` is the per-algorithm trailing
arc above. Source: FIPS 204 Algorithm 4 lines 12, 15, 18 (SHA-256 .01,
SHA-512 .03, SHAKE128 .0B); the remaining nine arcs are the matching
NIST CSOR registrations on the same OID branch.

### Domain Separation

HashML-DSA uses `domSep = 0x01` in M' (`M' = 0x01 ‖ |ctx| ‖ ctx ‖ OID ‖
PH_M`), distinct from pure ML-DSA's `domSep = 0x00`. This prevents a
cross-protocol attack where a forgery in one mode could transfer to the
other on the same key (FIPS 204 §3.6.4). The two modes are NOT
interchangeable, `verify()` will return `false` on the output of
`signHash()` and vice versa.

`ctx` is bound into M' alongside the OID and PH_M, but the caller's
message `M` is **only** seen by the pre-hash function, `ctx` is NOT
hashed. Use `ctx` for protocol-level domain separation (e.g. application
label, key purpose) and treat it as a public, attacker-known input.

### Example

```typescript
import { init, MlDsa65, randomBytes } from 'leviathan-crypto'
import { mldsaWasm } from 'leviathan-crypto/mldsa/embedded'
import { sha3Wasm }  from 'leviathan-crypto/sha3/embedded'
import { sha2Wasm }  from 'leviathan-crypto/sha2/embedded'

// SHA-2 prehash → all three modules required
await init({ mldsa: mldsaWasm, sha3: sha3Wasm, sha2: sha2Wasm })

const dsa = new MlDsa65()
const { signingKey, verificationKey } = dsa.keygen()

const M   = new TextEncoder().encode('protocol-bound payload')
const ctx = new TextEncoder().encode('application/v1')

// Hedged HashML-DSA over SHA-256
const sig = dsa.signHash(signingKey, M, 'SHA2-256', ctx)

const ok = dsa.verifyHash(verificationKey, M, sig, 'SHA2-256', ctx)
// ok === true

// Different ctx ⇒ verifyHash returns false (M' binds ctx).
dsa.verifyHash(verificationKey, M, sig, 'SHA2-256')              // false
// Different prehash ⇒ verifyHash returns false (M' binds OID).
dsa.verifyHash(verificationKey, M, sig, 'SHA3-256', ctx)         // false
// Pure verify on a HashML-DSA signature ⇒ false (M' binds 0x01 vs 0x00).
dsa.verify(verificationKey, M, sig, ctx)                          // false

dsa.dispose()
```

---

## Validation Behavior

ML-DSA distinguishes two failure classes, verification failures (binary,
return false) versus caller-contract violations (throw RangeError). The
split follows FIPS 204 §3.6.2 / §5.3 Algorithm 3.

| Condition                                | `sign()` / variants     | `verify()`              |
| ---------------------------------------- | ----------------------- | ----------------------- |
| `sk` length mismatch                     | throw `RangeError`      | n/a                     |
| `vk` length mismatch                     | n/a                     | return `false`          |
| `σ` length mismatch                      | n/a                     | return `false`          |
| `ctx.length > 255`                       | throw `RangeError`      | throw `RangeError`      |
| `rnd.length !== 32` (signDerand only)    | throw `RangeError`      | n/a                     |
| Malformed hint encoding (Alg 21 §D.3)    | n/a                     | return `false`          |
| Wrong signature for `(vk, M, ctx)`       | n/a                     | return `false`          |
| Norm bound `‖z‖∞ ≥ γ₁ − β`               | n/a                     | return `false`          |
| Unsupported `ph` (signHash* / verifyHash)| throw `RangeError`      | throw `RangeError`      |
| `sha2` not initialized + SHA-2 `ph`      | throw `Error`           | throw `Error`           |

Why the asymmetry: wrong-length pk/σ are *structural* indicators that the
input is not a valid ML-DSA signature, same verdict as a wrong signature.
Per FIPS 204 §3.6.2, both conditions return false. Oversize ctx, by
contrast, is a *caller* mistake (the caller built ctx, not an attacker)
and throws so the bug surfaces immediately.

The malformed-hint case is SUF-CMA-critical (FIPS 204 §D.3, added in the
final standard relative to the IPD draft). Algorithm 21 lines 4, 9, and
17 each gate against a distinct forgery surface; all three are enforced.

---

## Key & Signature Format

`verificationKey` (pk), FIPS 204 Algorithm 22 (pkEncode):

```
pk = ρ(32) ‖ SimpleBitPack(t₁[0]) ‖ SimpleBitPack(t₁[1]) ‖ … ‖ SimpleBitPack(t₁[k−1])
```

Each packed t₁[i] is `32 · (bitlen(q−1) − d) = 32 · 10 = 320` bytes. Total:
`32 + k · 320`.

`signingKey` (sk), FIPS 204 Algorithm 24 (skEncode):

```
sk = ρ(32) ‖ K(32) ‖ tr(64)
   ‖ BitPack(s₁[i], η, η)         × ℓ      each = 32 · bitlen(2η)
   ‖ BitPack(s₂[i], η, η)         × k
   ‖ BitPack(t₀[i], 2^(d−1)−1, 2^(d−1)) × k each = 32 · d = 416
```

The signing key includes `tr = H(pk, 64)` precomputed so signing does not
have to re-derive it. Treat the entire sk as private, compromise of any
component (especially ρ′ derivable from ξ, or s₁ derivable from sk) recovers
the full key.

The 32-byte seed ξ is *not* part of the published sk. Storing ξ is sufficient
to reconstruct the full key pair via `keygenDerand`, handle ξ with the same
care as sk.

`signature` (σ), FIPS 204 Algorithm 26 (sigEncode):

```
σ = c̃(λ/4) ‖ BitPack(z[i], γ₁−1, γ₁) × ℓ ‖ HintBitPack(h, ω, k)
```

- `c̃` is the SHAKE256-derived signature commitment hash (32, 48, or 64
  bytes for ML-DSA-44/65/87).
- Each packed `z[i]` is `32 · (1 + bitlen(γ₁−1))` bytes, 576 (γ₁=2¹⁷)
  or 640 (γ₁=2¹⁹).
- `HintBitPack(h, ω, k)` is exactly `ω + k` bytes.

Total signature size: `params.sigBytes` per parameter set.

---

## Wipe Discipline

Every `keygenDerand` call wipes:

- `SEED_OFFSET`, 128 bytes holding ρ ‖ ρ′ ‖ K (highest-severity residual:
  ρ′ expands to s₁/s₂; K is the per-message signing randomness).
- `TR_OFFSET`  , 64 bytes holding tr = H(pk, 64).
- `SK_OFFSET`  , `params.skBytes` holding the encoded sk (already returned
  to the caller; wipe shortens the in-WASM lifetime).
- `POLYVEC_SLOT_0`, s₁ in time-domain (ℓ × 1024 B).
- `POLYVEC_SLOT_1`, s₂ in time-domain (k × 1024 B).
- `POLYVEC_SLOT_2`, t intermediate (k × 1024 B).
- `POLYVEC_SLOT_4`, t₀ secret (k × 1024 B).
- `POLYVEC_SLOT_5`, ŝ₁ in NTT/Montgomery form (ℓ × 1024 B).
- `XOF_PRF_OFFSET`, 8 KiB SHAKE landing zone.

Public regions intentionally left alone: the matrix Â (derived from ρ which
is published in pk), the encoded pk, and t₁ (also published). The sha3
module's STATE/INPUT/OUT regions are wiped before return.

Every `sign` / `signDeterministic` / `signDerand` call wipes:

- All 6 polyvec slots, ŝ₁ / ŝ₂ / t̂₀ in tomont form, plus per-iteration
  intermediates: y, ⟨cs₁⟩, ⟨cs₂⟩, ⟨ct₀⟩, w, w − ⟨cs₂⟩, r₀, z, h.
- All 8 poly slots, including signs scratch (8 B from c̃), the c
  polynomial, and the polyvec_pointwise_acc_montgomery scratch in
  POLY_SLOT_7 which carries a partial product across y_ntt.
- `XOF_PRF_OFFSET`, last expandMask block (ρ''-derived) on rejected
  iterations or sample_in_ball position bytes (c̃-derived) on accepted.
- Defensive wipes on `SEED_OFFSET`, `TR_OFFSET`, `SK_OFFSET`,
  `C_TILDE_OFFSET`, `MSG_REP_OFFSET` even though sign does not actively
  write to them, closes any residue left by a prior op.
- TS-side wipes on local μ, ρ'', c̃, w₁ byte-slice via try/finally so
  they do not persist on the JS heap on early throw.

`verify` wipes the corresponding 5-slot polyvec range, the 8-slot poly
region, and the XOF buffer. Verify operates on public inputs (vk, σ, M,
ctx all public), so the wipe is hygiene rather than secrecy, but the
discipline matches sign so audits don't have to special-case verify.

`dispose()` wipes the entire mutable mldsa region, call it when you are
finished with the class.

---

## Error Reference

| Error                                                                                         | Cause                                                                          |
| --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `leviathan-crypto: call init({ mldsa: ... }) before using MlDsa classes`                      | Class constructor invoked before `init({ mldsa, sha3 })`.                      |
| `leviathan-crypto: call init({ sha3: ... }) before using MlDsa classes`                       | Init included `mldsa` but not `sha3`.                                          |
| `RangeError: xi seed must be 32 bytes (got N)`                                                | `keygenDerand(xi)` called with `xi.length !== 32`.                             |
| `RangeError: leviathan-crypto: signing key must be {N} bytes for {paramSet}`                  | `sign` / variants given a wrong-length sk.                                     |
| `RangeError: leviathan-crypto: ctx must be ≤ 255 bytes`                                       | `sign` or `verify` given a ctx longer than 255 bytes.                          |
| `RangeError: leviathan-crypto: rnd must be 32 bytes`                                          | `signDerand` given a rnd of wrong length.                                      |
| `leviathan-crypto: ML-DSA signing exceeded {N} rejection-sample iterations`                   | The rejection-sampling loop did not converge within the 1000-iteration bound. Indicates a malformed sk or extremely unlikely pathological seed; treat as a bug. |
| `leviathan-crypto: another stateful instance is using the 'sha3' WASM module, call dispose()`| A live `SHAKE128` / `SHAKE256` holds the sha3 module; release it first.        |
| `leviathan-crypto: mldsa MATRIX_SLOT too small for {paramSet} (needs N, have M)`              | Internal layout assertion. Indicates a build-time buffer-region misconfiguration. |

`verify` does NOT throw on signature failure, it returns `false`. Wrong-
length pk/σ also return `false` (FIPS 204 §3.6.2). See [Validation
Behavior](#validation-behavior) for the full split.

---

## SignatureSuites

The mldsa-suites layer wraps `MlDsaBase` into the `SignatureSuite` interface
for use with `Sign`, `SignStream`, and `VerifyStream`. Six suite consts ship:

- `MlDsa44Suite`, `MlDsa65Suite`, `MlDsa87Suite` for pure ML-DSA (FIPS 204 §5.2).
- `MlDsa44PreHashSuite`, `MlDsa65PreHashSuite`, `MlDsa87PreHashSuite` for
  HashML-DSA (FIPS 204 §5.4) with SHA3-256 (44, 65) or SHA3-512 (87).

The pure-mode suites satisfy `SignatureSuite` only; the prehash-mode suites
also satisfy `StreamableSignatureSuite` and plug into `SignStream` /
`VerifyStream`. Each method instantiates a fresh `MlDsa{44,65,87}` instance
inside a `try { ... } finally { dispose() }` block, so WASM key material is
wiped on every path.

See [signaturesuite.md](./signaturesuite.md) for the full `SignatureSuite`
interface, wire format, error reference, and usage examples.

---

## Cross-references

- [Architecture](./architecture.md), module layout and three-tier design.
- [init.md](./init.md), `init()` API and module-loader contract.
- [signaturesuite.md](./signaturesuite.md), `SignatureSuite` interface plus
  the `MlDsa*Suite` consts, `Sign`, `SignStream`, and `VerifyStream`.
- [asm_mldsa.md](./asm_mldsa.md), low-level WASM module reference.
- [kyber.md](./kyber.md), sibling post-quantum module (KEM, not signatures).
