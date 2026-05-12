<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### SLH-DSA (SPHINCS+): Post-Quantum Hash-Based Signatures

Post-quantum digital signatures via SLH-DSA (FIPS 205), the NIST-standardized
stateless hash-based signature scheme. Security rests on the preimage and
collision resistance of SHAKE; no lattice or number-theoretic assumption is
involved.

> ### Table of Contents
> - [Overview](#overview)
> - [Parameter Sets](#parameter-sets)
> - [Init](#init)
> - [SlhDsa API](#slhdsa-api)
> - [HashSLH-DSA (Pre-Hash Variant)](#hashslh-dsa-pre-hash-variant)
> - [Validation Behavior](#validation-behavior)
> - [Key & Signature Format](#key--signature-format)
> - [Wipe Discipline](#wipe-discipline)
> - [Performance](#performance)
> - [Error Reference](#error-reference)
> - [SignatureSuites](#signaturesuites)
> - [Cross-references](#cross-references)

---

## Overview

SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) is a hash-based
signature scheme standardized by NIST in FIPS 205. It is the post-quantum
counterpart to RSA and ECDSA whose only assumption is the security of the
underlying hash function: existential unforgeability under chosen-message
attack (EUF-CMA) follows from preimage and collision resistance of SHAKE.
Grover's algorithm provides at most a quadratic speedup against preimage
search, leaving each parameter set with roughly half its classical bit
security in the quantum setting (FIPS 205 §1.2 / §11.1).

This module exposes three classes, `SlhDsa128f`, `SlhDsa192f`, and
`SlhDsa256f`, covering the three FIPS 205 SHAKE fast parameter sets. Phase 2
ships the fast (`f`) SHAKE variants only; the slow (`s`) variants and the
SHA-2 family from FIPS 205 §11.2 Table 5 are out of scope. Each class
supports pure SLH-DSA (FIPS 205 §10.1) and HashSLH-DSA (FIPS 205 §10.2, the
pre-hash variant) across the three signing modes: hedged, deterministic,
and externally-randomized.

Verification against the NIST ACVP corpora pins the implementation to FIPS
205 byte-for-byte:

- ACVP-Server pin: `15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0` (v1.1.0.42, 2026-04-16).
- 15 keyGen-FIPS205 vectors (5 AFT per parameter set).
- 39 sigGen-FIPS205 vectors (per parameter set: 5 pure-deterministic, 5 pure-hedged, 3 preHash-deterministic).
- 27 sigVer-FIPS205 vectors covering positive and known-fail cases (per parameter set: 2 pure-pass, 3 pure-fail, 2 preHash-pass, 2 preHash-fail).

The hybrid PQ-only suites (`MlDsa44SlhDsa128fSuite`,
`MlDsa65SlhDsa192fSuite`, `MlDsa87SlhDsa256fSuite`) compose this module with
ML-DSA at the matching security category. See
[signaturesuite.md](./signaturesuite.md) for the suite-layer surface and
[SECURITY.md](../SECURITY.md) for the PQ-only hybrid threat model.

---

## Parameter Sets

| Class         | NIST Name             | n  | h  | d  | h' | k  | a | m  | pkBytes | skBytes | sigBytes | Security    |
|---------------|-----------------------|----|----|----|----|----|---|----|---------|---------|----------|-------------|
| `SlhDsa128f`  | SLH-DSA-SHAKE-128f    | 16 | 66 | 22 | 3  | 33 | 6 | 30 | 32      | 64      | 17088    | Category 1  |
| `SlhDsa192f`  | SLH-DSA-SHAKE-192f    | 24 | 66 | 22 | 3  | 33 | 8 | 39 | 48      | 96      | 35664    | Category 3  |
| `SlhDsa256f`  | SLH-DSA-SHAKE-256f    | 32 | 68 | 17 | 4  | 35 | 9 | 49 | 64      | 128     | 49856    | Category 5  |

Numeric values are FIPS 205 §11.1 Table 2. Symbol meanings: `n` is the
security parameter in bytes; `h` is the total hypertree height; `d` is the
hypertree layer count; `h'` is the per-XMSS-subtree height (`h/d`); `k` is
the number of FORS trees; `a` is the FORS tree height in bits; `m` is the
H_msg output length. Derived sizes: `pkBytes = 2·n`, `skBytes = 4·n`,
`sigBytes = (1 + k·(a+1) + h + d·len)·n` with `len = 2·n + 3`.

Pick `SlhDsa192f` (category 3) as a general-purpose default at security
parity with `MlDsa65`. `SlhDsa128f` (category 1) is the smallest
hash-based signature available but still slow; reach for it only when
category 1 is acceptable and signature size budget is tight. `SlhDsa256f`
(category 5) is the highest assurance fast variant for long-lived keys.

> [!NOTE]
> SLH-DSA signatures are large: 17 KiB at the smallest setting, nearly
> 50 KiB at the largest. ML-DSA signatures range from 2.4 to 4.6 KiB. The
> hash-based design that makes SLH-DSA cryptanalytically conservative is
> the same property that drives the size. Use SLH-DSA when its assumption
> diversity matters; pair it with ML-DSA via the hybrid suites when both
> properties matter.

---

## Init

```typescript
import { init }       from 'leviathan-crypto'
import { slhdsaWasm } from 'leviathan-crypto/slhdsa/embedded'

await init({ slhdsa: slhdsaWasm })
```

Pure SLH-DSA needs only the `slhdsa` module. The WASM binary embeds its own
Keccak permutation for the §11.2 F / H / T_ℓ / PRF / PRF_msg / H_msg tweakable
hash family, so no separate `sha3` slot is required for the core algorithm.

HashSLH-DSA with a SHA-3 or SHAKE pre-hash additionally requires `sha3`:

```typescript
import { sha3Wasm } from 'leviathan-crypto/sha3/embedded'

await init({ slhdsa: slhdsaWasm, sha3: sha3Wasm })
```

HashSLH-DSA with a SHA-2 family pre-hash additionally requires `sha2`:

```typescript
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await init({ slhdsa: slhdsaWasm, sha3: sha3Wasm, sha2: sha2Wasm })
```

For tree-shakeable imports the `leviathan-crypto/slhdsa` subpath exports
its own init function:

```typescript
import { slhdsaInit } from 'leviathan-crypto/slhdsa'
import { slhdsaWasm } from 'leviathan-crypto/slhdsa/embedded'

await slhdsaInit(slhdsaWasm)
```

`slhdsaInit(source)` initializes only the slhdsa WASM binary. Calling
HashSLH-DSA with a SHA-3 / SHAKE pre-hash before initializing `sha3`, or
with a SHA-2 pre-hash before initializing `sha2`, throws a clear error
rather than silently mis-signing.

SLH-DSA runs on any WASM-capable runtime. The slhdsa module does not use
WebAssembly SIMD; the SHAKE-driven hash family compiles to scalar
operations across all hosts.

---

## SlhDsa API

All three classes share the same surface, defined by the `SlhDsaBase`
parent. Construction is parameter-less; the parameter set is fixed by the
class.

### Constructor

```typescript
new SlhDsa128f()
new SlhDsa192f()
new SlhDsa256f()
```

Throws if `init({ slhdsa })` has not been called. Cheap, runs a
parameter-set lookup against the slhdsa exports and returns.

### `keygen(): SlhDsaKeyPair`

Generate a new key pair using a fresh 3·n-byte seed from
`crypto.getRandomValues`. Wraps `keygenDerand` with `randomBytes(3·n)`
and wipes the local seed on return.

```typescript
const dsa = new SlhDsa192f()
const { verificationKey, signingKey } = dsa.keygen()
// verificationKey: 48-byte pk = PK.seed || PK.root (FIPS 205 §9.1)
// signingKey:      96-byte sk = SK.seed || SK.prf || PK.seed || PK.root
dsa.dispose()
```

### `keygenDerand(seed: Uint8Array): SlhDsaKeyPair`

Deterministic key generation, FIPS 205 §9.1 Algorithm 18
(`slh_keygen_internal`). The 3·n-byte seed is the concatenation
`SK.seed || SK.prf || PK.seed`. Each component is `n` bytes for the
parameter set (16, 24, or 32). Use this when the seed comes from an
external source: ACVP vectors, key escrow, deterministic deployments.
Throws `RangeError` on a wrong-length seed.

```typescript
const seed = new Uint8Array(3 * 24)
crypto.getRandomValues(seed)

const dsa = new SlhDsa192f()
const { verificationKey, signingKey } = dsa.keygenDerand(seed)
dsa.dispose()
seed.fill(0)  // SK.seed and SK.prf are the master secrets; wipe after use
```

### `sign(sk, M, ctx?): Uint8Array`

Hedged signing, FIPS 205 §10.1 Algorithm 22 (`slh_sign`) composed with
§9.2 Algorithm 19 (`slh_sign_internal`). Produces a signature of
`params.sigBytes` bytes. Each call sources a fresh `n`-byte `addrnd`
(`opt_rand` in the spec) from `crypto.getRandomValues`, feeds it into
PRF_msg alongside SK.prf, and wipes the local randomness buffer on
return. Two `sign()` calls over the same `(sk, M, ctx)` return different
bytes; both verify.

```typescript
const dsa = new SlhDsa192f()
const { verificationKey, signingKey } = dsa.keygen()
const sig = dsa.sign(signingKey, message)
const ok  = dsa.verify(verificationKey, message, sig)   // true
dsa.dispose()
```

Hedged signing is preferred over deterministic per FIPS 205 §3.4 / §9.2:
hedged signatures remain unforgeable against fault attacks that bias
secret-derived intermediates, where deterministic signatures do not.

`ctx` defaults to an empty Uint8Array. Caller-supplied ctx must be ≤ 255
bytes per FIPS 205 §10.1 Algorithm 22 line 1; longer values throw
`SigningError('sig-ctx-too-long')`. The signature binds `(M, ctx)`;
verifying with a different ctx returns false.

### `signDeterministic(sk, M, ctx?): Uint8Array`

Deterministic signing, FIPS 205 §3.4. Sets `opt_rand ← PK.seed` (sliced
from the encoded `sk`) so two signatures over the same `(sk, M, ctx)`
return identical bytes.

```typescript
const sig1 = dsa.signDeterministic(signingKey, message)
const sig2 = dsa.signDeterministic(signingKey, message)
// sig1 === sig2 byte-for-byte
```

> [!CAUTION]
> Deterministic signatures are vulnerable to fault attacks per FIPS 205
> §3.4 / §9.2. Use only when no entropy source is available (embedded
> boot, hard reproducibility requirement) or when running CAVP / ACVP
> tests. Prefer `sign()` for production.

### `signDerand(sk, M, optRand, ctx?): Uint8Array`

Externally-randomized signing, the testing / CAVP entry point. Caller
supplies the `n`-byte `optRand`; the library does not mix in additional
entropy.

```typescript
const optRand = randomBytes(dsa.params.n)
const sig = dsa.signDerand(signingKey, message, optRand, ctx)
```

> [!CAUTION]
> Hard contract on the caller: `optRand` MUST come from an approved RBG
> (FIPS 205 §3.4) and MUST NOT be reused across signatures. Reuse
> degrades the hedging property and may degenerate to the deterministic
> case with attacker-controlled randomness. The library does not enforce
> single-use; the caller owns this discipline.

### `verify(pk, M, sig, ctx?): boolean`

Pure SLH-DSA verify, FIPS 205 §10.3 Algorithm 24 composed with §9.3
Algorithm 20 (`slh_verify_internal`). Returns `true` only if every WOTS+
chain, FORS Merkle path, XMSS auth path, and hypertree layer reconstructs
back to the encoded PK.root.

```typescript
const ok = dsa.verify(verificationKey, message, sig, ctx)   // boolean
```

`verify` returns `false` on a wrong signature, throws on a caller-side
contract violation. See [Validation Behavior](#validation-behavior) for
the exact split.

### `signHash(sk, M, ph, ctx?): Uint8Array`

Hedged HashSLH-DSA sign, FIPS 205 §10.2.2 Algorithm 23 (`hash_slh_sign`).
Pre-hashes `M` with the caller-selected approved function `ph`, builds
`M' = 0x01 || |ctx| || ctx || OID(ph) || PH_M`, and drives
`slh_sign_internal` with a fresh `n`-byte `addrnd` (same hedged-versus-
deterministic rationale as [`sign`](#signsk-m-ctx-uint8array)).

```typescript
import { SlhDsa192f } from 'leviathan-crypto'

const dsa = new SlhDsa192f()
const { signingKey, verificationKey } = dsa.keygen()
const sig = dsa.signHash(signingKey, message, 'SHAKE256')
const ok  = dsa.verifyHash(verificationKey, message, sig, 'SHAKE256')
dsa.dispose()
```

`ph` is required and immediately follows the bytes it operates on (`M`
for sign, `sig` for verify). The 12 approved §10.2.2 choices have no
cryptographic priority, so callers must select one explicitly; there is
no default. `ctx` trails as an optional parameter so the common-case
empty-ctx call reads cleanly. See
[Pre-Hash Algorithms](#pre-hash-algorithms) for the full list, module
dependencies, and category restrictions.

### `signHashDeterministic(sk, M, ph, ctx?): Uint8Array`

Deterministic HashSLH-DSA sign, FIPS 205 §10.2.2 Algorithm 23 with
`opt_rand ← PK.seed`. Same fault-attack caveat as
[`signDeterministic`](#signdeterministicsk-m-ctx-uint8array).

### `signHashDerand(sk, M, ph, optRand, ctx?): Uint8Array`

Externally-randomized HashSLH-DSA sign, testing / CAVP API. Caller
supplies the `n`-byte `optRand`; same contract as
[`signDerand`](#signderandsk-m-optrand-ctx-uint8array). Used to oracle
ACVP HashSLH-DSA sigGen vectors with byte-identical output.

### `verifyHash(pk, M, sig, ph, ctx?): boolean`

HashSLH-DSA verify, FIPS 205 §10.3 Algorithm 25 (`hash_slh_verify`).
Same return / throw posture as
[`verify`](#verifypk-m-sig-ctx-boolean): returns boolean for every
signature outcome (wrong sig, malformed encoding, wrong-length pk / sig
per §3.6.2), throws `RangeError` only on caller-side contract violations
(`ctx.length > 255`, unsupported `ph`, category mismatch).

> [!CAUTION]
> **Pure-SLH-DSA and HashSLH-DSA signatures are not interchangeable**
> even on the same key. The M' construction binds a different domain-sep
> byte (`0x00` for pure, `0x01` for HashSLH-DSA per FIPS 205 §10.2
> narrative). A signature produced by `sign` does NOT verify under
> `verifyHash` and vice versa. Treat the two as separate signature
> schemes that share a key format.

### `signHashPrehashed(sk, digest, ph, ctx?): Uint8Array`

Hedged HashSLH-DSA sign with a caller-supplied prehash, FIPS 205 §10.2.2
Algorithm 23 lines 18-25 (the post-PH path). Skips the internal
`PH ← H_PH(M)` step and uses `digest` directly. Identical
`slh_sign_internal` output to
[`signHash`](#signhashsk-m-ph-ctx-uint8array) when `digest = H_PH(M)`.

`digest` must be exactly the FIPS 205 §10.2.2 output length for `ph`:
28 bytes for `SHA2-224` / `SHA2-512/224` / `SHA3-224`, 32 bytes for
`SHA2-256` / `SHA2-512/256` / `SHA3-256` / `SHAKE128`, 48 bytes for
`SHA2-384` / `SHA3-384`, 64 bytes for `SHA2-512` / `SHA3-512` /
`SHAKE256`. A mismatch throws
[`SigningError('sig-malformed-input')`](#error-reference). The caller
owns `digest` and is responsible for wiping it; the method never mutates
the buffer.

Use this entry point when:

- The transcript already produced the digest as part of a protocol step.
- The signer cannot buffer `M` into a single `Uint8Array` (a `SignStream`-
  style API computes the prehash incrementally and hands `signHashPrehashed`
  the finalized digest).
- A FIPS 140 boundary places the digest computation in a different module
  from SLH-DSA, FIPS 205 §10.2.2 explicitly endorses the split.

### `signHashPrehashedDeterministic(sk, digest, ph, ctx?): Uint8Array`

Deterministic prehashed sign, `opt_rand ← PK.seed` per FIPS 205 §3.4.
Same fault-attack caveat as
[`signDeterministic`](#signdeterministicsk-m-ctx-uint8array). Produces
byte-identical output to
[`signHashDeterministic`](#signhashdeterministicsk-m-ph-ctx-uint8array)
when `digest = H_PH(M)`.

### `signHashPrehashedDerand(sk, digest, ph, optRand, ctx?): Uint8Array`

Externally-randomized prehashed sign, testing / CAVP API. Caller
supplies the `n`-byte `optRand` (FIPS 205 §3.4 contract: `optRand` MUST
come from an approved RBG and MUST NOT be reused across signatures).

### `verifyHashPrehashed(pk, digest, sig, ph, ctx?): boolean`

HashSLH-DSA verify with a caller-supplied prehash, FIPS 205 §10.3
Algorithm 25 lines 16-19 (the post-PH path). Same return / throw posture
as [`verifyHash`](#verifyhashpk-m-sig-ph-ctx-boolean): returns boolean
for every signature outcome; throws `RangeError` only on caller-side
contract violations (`ctx.length > 255`, unsupported `ph`, category
mismatch).

Wrong-size `digest` is a structural mismatch (a different-shaped M'
than the signer would have produced) and returns `false`, mirroring how
wrong-length pk / sig return `false` per FIPS 205 §3.6.2. This DIVERGES
from the sign-side behaviour, which throws `SigningError` on wrong-size
`digest`: on the sign side the caller fed bad input; on the verify side,
"this is not a valid signature" is the correct verdict.

> [!CAUTION]
> The prehashed family signs `digest` *as if* it were `H_PH(M)`; the
> library cannot check whether `digest` actually equals that hash. A
> protocol that wants to bind a specific `M` MUST compute the digest
> itself (or verify the digest's provenance) before calling these
> methods; otherwise an attacker that controls `digest` can produce a
> signature that is consistent with any preimage they later choose.

### `dispose(): void`

Final hygiene pass on the slhdsa WASM scratch region. `SlhDsaBase` is
atomic-only (no per-instance state beyond the readonly `params`); every
public method already runs `wipeBuffers()` in its own `finally`, so
`dispose()` is defence-in-depth rather than a state-lifecycle hook.
Idempotent and safe to call multiple times. Never throws.

### Field: `params: SlhDsaParams`

Read-only parameter-set constants:

```typescript
interface SlhDsaParams {
    paramSet:         'SLH-DSA-SHAKE-128f' | 'SLH-DSA-SHAKE-192f' | 'SLH-DSA-SHAKE-256f'
    n:                number   // security parameter in bytes
    h:                number   // total hypertree height
    d:                number   // hypertree layer count
    hPrime:           number   // XMSS subtree height (h/d)
    k:                number   // number of FORS trees
    a:                number   // FORS tree height in bits
    m:                number   // H_msg output length in bytes
    pkBytes:          number   // 2·n
    skBytes:          number   // 4·n
    sigBytes:         number   // (1 + k·(a+1) + h + d·len)·n
    securityCategory: 1 | 3 | 5
    wasmSelector:     () => void
}
```

`wasmSelector` is an internal binder that writes the parameter set into
the WASM PARAMS slot before every public algorithm call; users should
treat it as opaque.

---

## HashSLH-DSA (Pre-Hash Variant)

HashSLH-DSA, FIPS 205 §10.2.2, wraps the same `slh_sign_internal` /
`slh_verify_internal` primitives pure SLH-DSA uses, but pre-hashes the
message with a caller-selected approved function and prefixes M' with the
function's OID DER bytes plus a different domain-sep byte. The four
public methods [`signHash`](#signhashsk-m-ph-ctx-uint8array),
[`signHashDeterministic`](#signhashdeterministicsk-m-ph-ctx-uint8array),
[`signHashDerand`](#signhashderandsk-m-ph-optrand-ctx-uint8array), and
[`verifyHash`](#verifyhashpk-m-sig-ph-ctx-boolean) match the shape of
their pure counterparts with `ph: PreHashAlgorithm` placed immediately
after the message bytes (or signature, for verify).

Four parallel prehashed-input variants
([`signHashPrehashed`](#signhashprehashedsk-digest-ph-ctx-uint8array),
[`signHashPrehashedDeterministic`](#signhashprehasheddeterministicsk-digest-ph-ctx-uint8array),
[`signHashPrehashedDerand`](#signhashprehashedderandsk-digest-ph-optrand-ctx-uint8array),
and
[`verifyHashPrehashed`](#verifyhashprehashedpk-digest-sig-ph-ctx-boolean))
skip the internal `PH ← H_PH(M)` step and accept the digest from the
caller. Use these when the digest already exists (a streaming signer
that absorbed `M` incrementally, a transcript that carries the digest as
its identifier, or a FIPS 140 boundary that computes the hash in a
separate module). When `digest = H_PH(M)`, the prehashed and
non-prehashed forms produce byte-identical signatures.

Use HashSLH-DSA when:

- The caller cannot stream the full message into a single `Uint8Array`
  before signing (a hash digest is constant-size).
- A protocol identifier prescribes a specific pre-hash function (e.g.
  X.509 CMS / S/MIME signature suites identifying the digest by OID).
- A FIPS 140 boundary forces the digest computation into a different
  cryptographic module from SLH-DSA itself.

Use pure SLH-DSA otherwise: it elides one hashing pass and avoids the
collision-resistance margin question entirely.

### Pre-Hash Algorithms

The 12 approved pre-hash functions (FIPS 205 §10.2.2) and the OID DER
trailing arc on the shared 2.16.840.1.101.3.4.2.x branch:

| `PreHashAlgorithm`  | OID arc | Output bytes | Required init                          | Allowed categories |
| ------------------- | ------- | ------------ | -------------------------------------- | ------------------ |
| `'SHA2-224'`        | .04     | 28           | `init({ slhdsa, sha2 })`               | 1, 3, 5            |
| `'SHA2-256'`        | .01     | 32           | `init({ slhdsa, sha2 })`               | 1 only             |
| `'SHA2-384'`        | .02     | 48           | `init({ slhdsa, sha2 })`               | 1, 3, 5            |
| `'SHA2-512'`        | .03     | 64           | `init({ slhdsa, sha2 })`               | 1, 3, 5            |
| `'SHA2-512/224'`    | .05     | 28           | `init({ slhdsa, sha2 })`               | 1, 3, 5            |
| `'SHA2-512/256'`    | .06     | 32           | `init({ slhdsa, sha2 })`               | 1, 3, 5            |
| `'SHA3-224'`        | .07     | 28           | `init({ slhdsa, sha3 })`               | 1, 3, 5            |
| `'SHA3-256'`        | .08     | 32           | `init({ slhdsa, sha3 })`               | 1, 3, 5            |
| `'SHA3-384'`        | .09     | 48           | `init({ slhdsa, sha3 })`               | 1, 3, 5            |
| `'SHA3-512'`        | .0A     | 64           | `init({ slhdsa, sha3 })`               | 1, 3, 5            |
| `'SHAKE128'`        | .0B     | 32 (256-bit) | `init({ slhdsa, sha3 })`               | 1 only             |
| `'SHAKE256'`        | .0C     | 64 (512-bit) | `init({ slhdsa, sha3 })`               | 1, 3, 5            |

The leviathan-crypto `init({ ... })` cache validates `sha2` only when
the caller actually uses a SHA-2 family pre-hash. Pure SLH-DSA usage
and SHA-3 / SHAKE-prehash HashSLH-DSA usage need neither.

> [!IMPORTANT]
> Per FIPS 205 §10.2.2: "SHA-256 and SHAKE128 are only appropriate for
> use with SLH-DSA parameter sets that are claimed to be in security
> category 1." `SlhDsa192f` (category 3) and `SlhDsa256f` (category 5)
> reject `'SHA2-256'` and `'SHAKE128'` at the public surface with a
> clear `RangeError`. The library enforces this gate before any signing
> call so the digest size cannot drop below the parameter set's
> security floor.

OID DER prefix: every entry is the 11-byte sequence
`06 09 60 86 48 01 65 03 04 02 NN`, the first 10 bytes are
`OBJECT IDENTIFIER (length 9) || joint-iso-itu-t.country.us.organization
.gov.csor.nistalgorithm.hashalgs`, and `NN` is the per-algorithm trailing
arc above. Source: FIPS 205 §10.2.2 Algorithm 23 lines 10, 13, 16, 19
enumerate SHA-256 (.01), SHA-512 (.03), SHAKE128 (.0B), SHAKE256 (.0C)
by example; the remaining eight arcs are the matching NIST CSOR
registrations on the same OID branch. The OID layout is byte-identical
to FIPS 204 §5.4 HashML-DSA's, so a hybrid suite signing the same
prehash under both primitives sees byte-identical M' bytes.

### Domain Separation

HashSLH-DSA uses `domSep = 0x01` in M'
(`M' = 0x01 || |ctx| || ctx || OID || PH_M`), distinct from pure
SLH-DSA's `domSep = 0x00`. This prevents a cross-protocol attack where
a forgery in one mode could transfer to the other on the same key (FIPS
205 §10.2 narrative). The two modes are NOT interchangeable; `verify()`
returns `false` on the output of `signHash()` and vice versa.

`ctx` is bound into M' alongside the OID and PH_M, but the caller's
message `M` is **only** seen by the pre-hash function; `ctx` is NOT
hashed. Use `ctx` for protocol-level domain separation (application
label, key purpose) and treat it as a public, attacker-known input.

### Example

```typescript
import { init, SlhDsa192f, randomBytes } from 'leviathan-crypto'
import { slhdsaWasm } from 'leviathan-crypto/slhdsa/embedded'
import { sha3Wasm }   from 'leviathan-crypto/sha3/embedded'

await init({ slhdsa: slhdsaWasm, sha3: sha3Wasm })

const dsa = new SlhDsa192f()
const { signingKey, verificationKey } = dsa.keygen()

const M   = new TextEncoder().encode('protocol-bound payload')
const ctx = new TextEncoder().encode('application/v1')

const sig = dsa.signHash(signingKey, M, 'SHAKE256', ctx)

const ok = dsa.verifyHash(verificationKey, M, sig, 'SHAKE256', ctx)
// ok === true

dsa.verifyHash(verificationKey, M, sig, 'SHAKE256')              // false (different ctx)
dsa.verifyHash(verificationKey, M, sig, 'SHA3-512', ctx)         // false (different OID)
dsa.verify(verificationKey, M, sig, ctx)                          // false (pure vs hash domSep)

dsa.dispose()
```

---

## Validation Behavior

SLH-DSA distinguishes two failure classes: verification failures (binary,
return false) versus caller-contract violations (throw). The split follows
FIPS 205 §3.6.2 / §10.3.

| Condition                                | `sign()` / variants          | `verify()`                   |
| ---------------------------------------- | ---------------------------- | ---------------------------- |
| `sk` length mismatch                     | throw `RangeError`           | n/a                          |
| `pk` length mismatch                     | n/a                          | return `false`               |
| `σ` length mismatch                      | n/a                          | return `false`               |
| `ctx.length > 255`                       | throw `SigningError`         | throw `SigningError`         |
| `optRand.length !== n` (signDerand only) | throw `RangeError`           | n/a                          |
| Wrong-size digest (prehashed sign)       | throw `SigningError`         | n/a                          |
| Wrong-size digest (prehashed verify)     | n/a                          | return `false`               |
| Wrong signature for `(pk, M, ctx)`       | n/a                          | return `false`               |
| Unsupported `ph` (signHash* / verifyHash)| throw `RangeError`           | throw `RangeError`           |
| Category mismatch (SHA-256 / SHAKE128 on cat≠1) | throw `RangeError`    | throw `RangeError`           |
| `sha2` not initialized + SHA-2 `ph`      | throw `Error`                | throw `Error`                |
| `sha3` not initialized + SHA-3 / SHAKE `ph` | throw `Error`             | throw `Error`                |

Why the asymmetry: wrong-length pk / σ / digest are *structural*
indicators that the input is not a valid SLH-DSA signature, same verdict
as a wrong signature. Per FIPS 205 §3.6.2, both conditions return false.
Oversize ctx, by contrast, is a *caller* mistake and throws so the bug
surfaces immediately. Category mismatches are caller mistakes per FIPS
205 §10.2.2, so they throw rather than silently fall through to a verify
failure.

---

## Key & Signature Format

`verificationKey` (pk), FIPS 205 §9.1 Algorithm 17:

```
pk = PK.seed (n) || PK.root (n)
```

Total: `pkBytes = 2·n`.

`signingKey` (sk), FIPS 205 §9.1 Algorithm 17:

```
sk = SK.seed (n) || SK.prf (n) || PK.seed (n) || PK.root (n)
```

Total: `skBytes = 4·n`. The sk re-embeds the entire pk so signing does
not need a separate public-key argument. `SK.seed` and `SK.prf` are the
master secrets; compromise of either recovers the full signing key.
`PK.seed` and `PK.root` are public.

The 3·n-byte `keygenDerand` seed is `SK.seed || SK.prf || PK.seed`. Storing
just this seed is sufficient to reconstruct the full key pair; handle the
seed with the same care as the encoded sk.

`signature` (σ), FIPS 205 §9.2 Algorithm 19:

```
σ = R (n) || σ_FORS (k·(a+1)·n) || σ_HT ((h + d·len)·n)
```

where `len = 2·n + 3` is the WOTS+ chain count.

- `R` is the per-message randomness from PRF_msg.
- `σ_FORS` is `k` FORS authentication paths, each of height `a`.
- `σ_HT` is `d` XMSS subtree signatures, each `(len + h')·n` bytes.

Total signature size: `params.sigBytes` per parameter set.

---

## Wipe Discipline

The lib never wipes caller-supplied buffers (`sk`, `M`, `ctx`, `digest`,
externally-supplied `optRand`). Those remain the caller's responsibility
under the library-wide memory-hygiene contract.

Every public method runs the same per-call hygiene cycle:

- INPUT region of the slhdsa WASM module is filled with zeros in the
  `finally` block. INPUT held the encoded sk on sign paths, encoded pk
  on verify paths, the M' bytes (which include ctx + message or ctx +
  OID + prehash), and the staging copy of `optRand`. All are wiped
  unconditionally.
- `wipeBuffers()` on the slhdsa WASM module zeros the OUT, STATE, and
  SCRATCH regions. These hold every WOTS+ chain intermediate, every
  FORS Merkle node, every XMSS subtree authentication node, the
  hypertree-layer XMSS roots, the H_msg digest, and the per-call ADRS
  scratch.
- The lib-allocated M' Uint8Array is wiped before return; M' contains
  the caller's ctx and either the raw message or the prehash digest.
- For `keygenDerand`, the INPUT region holding `SK.seed || SK.prf ||
  PK.seed` is wiped after the keygen completes.
- For hedged sign paths, the lib-generated `optRand` Uint8Array is
  wiped after the WASM call. For deterministic paths, the `optRand`
  slice (a copy of `PK.seed` from sk) is wiped for hygiene even though
  PK.seed is public.
- For HashSLH-DSA paths, the PH_M digest buffer the lib computed
  internally is wiped after `slh_sign_internal` / `slh_verify_internal`
  returns. The sha3 and sha2 module scratch buffers are wiped via
  their `wipeBuffers` exports when the chosen `ph` routes through them.

`dispose()` runs a final `wipeBuffers()` for defence-in-depth. The
module's exclusivity guard ensures no other instance is using the
slhdsa WASM module while a `SlhDsaBase` operation is in flight, so the
wipe cannot race with a concurrent reader.

---

## Performance

SLH-DSA is materially slower than ML-DSA because every signature
involves tens of thousands of SHAKE invocations across the FORS,
XMSS, and hypertree layers. Verify is roughly an order of magnitude
faster than sign for all three parameter sets. Indicative ranges:

```
SLH-DSA-128f sign:   ~5-10 ms native, ~10-20 ms WASM
SLH-DSA-192f sign:   ~12-20 ms native, ~24-40 ms WASM
SLH-DSA-256f sign:   ~25-40 ms native, ~50-80 ms WASM
Verify is roughly 10x faster than sign across all three.
Hybrid sign cost = SLH-DSA cost + ML-DSA cost (~1 ms).
```

The actual numbers in your environment depend on the host's SHAKE
throughput and the JIT's WASM tier. Run the per-suite benchmarks under
`scripts/` if you need ground-truth numbers for capacity planning.

---

## Error Reference

| Error                                                                                              | Cause                                                                          |
| -------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `leviathan-crypto: call init({ slhdsa: ... }) before using SlhDsa classes`                          | Class constructor invoked before `init({ slhdsa })`.                           |
| `RangeError: leviathan-crypto: keygen seed must be {3n} bytes ... for {paramSet} (got N)`           | `keygenDerand(seed)` called with `seed.length !== 3·n`.                        |
| `RangeError: leviathan-crypto: signing key must be {N} bytes for {paramSet}`                        | `sign` / variants given a wrong-length sk.                                     |
| `SigningError('sig-ctx-too-long')`                                                                  | `sign` / `verify` / variants given a ctx longer than 255 bytes.                |
| `RangeError: leviathan-crypto: opt_rand must be {n} bytes for {paramSet}`                           | `signDerand` / `signHashDerand` / `signHashPrehashedDerand` given a wrong-length optRand. |
| `SigningError('sig-malformed-input')`                                                               | Prehashed sign given a digest whose length does not match `digestSize(ph)`.   |
| `RangeError: leviathan-crypto: HashSLH-DSA pre-hash 'X' is only appropriate for security category 1 ...` | `signHash*` / `verifyHash*` called with `SHA2-256` or `SHAKE128` on a non-cat-1 class. |
| `RangeError: leviathan-crypto: unsupported HashSLH-DSA pre-hash algorithm 'X'`                      | `ph` is not one of the 12 FIPS 205 §10.2.2 entries.                            |
| `leviathan-crypto: call init({ sha2: ... }) before HashSLH-DSA with SHA-2 pre-hash`                 | `signHash*` / `verifyHash*` with a SHA-2 `ph` before `sha2` init.              |
| `leviathan-crypto: call init({ sha3: ... }) before HashSLH-DSA with SHA-3 / SHAKE pre-hash`         | `signHash*` / `verifyHash*` with a SHA-3 / SHAKE `ph` before `sha3` init.      |
| `leviathan-crypto: another stateful instance is using the 'slhdsa' WASM module, call dispose()`     | A live SlhDsa* operation holds the exclusivity token.                          |

`verify` does NOT throw on signature failure; it returns `false`.
Wrong-length pk / σ / digest also return `false` (FIPS 205 §3.6.2). See
[Validation Behavior](#validation-behavior) for the full split.

---

## SignatureSuites

The slhdsa-suites layer wraps `SlhDsaBase` into the `SignatureSuite`
interface for use with `Sign`, `SignStream`, and `VerifyStream`. Six
suite consts ship in Phase 2:

- `SlhDsa128fSuite`, `SlhDsa192fSuite`, `SlhDsa256fSuite` for pure
  SLH-DSA (FIPS 205 §10.1).
- `SlhDsa128fPreHashSuite`, `SlhDsa192fPreHashSuite`,
  `SlhDsa256fPreHashSuite` for HashSLH-DSA (FIPS 205 §10.2) with
  SHAKE128 (128f) or SHAKE256 (192f, 256f).

Three additional PQ-only hybrid suites compose SLH-DSA with ML-DSA at
each NIST security category:

- `MlDsa44SlhDsa128fSuite` (`0x30`, category 1).
- `MlDsa65SlhDsa192fSuite` (`0x31`, category 3).
- `MlDsa87SlhDsa256fSuite` (`0x32`, category 5).

The hybrid suites sign the same prehash under both primitives so a
break in one PQ family does not compromise the combined signature. See
[signaturesuite.md](./signaturesuite.md#pq-only-hybrid-composite-encoding)
for the wire format and
[SECURITY.md](../SECURITY.md#pq-only-hybrid-signature-threat-model) for
the threat model.

The pure-mode suites satisfy `SignatureSuite` only; the prehash-mode
and hybrid suites also satisfy `StreamableSignatureSuite` and plug into
`SignStream` / `VerifyStream`. Each method instantiates a fresh
`SlhDsa{128f,192f,256f}` instance inside a
`try { ... } finally { dispose() }` block so WASM scratch is wiped on
every path.

---

## Cross-references

- [Architecture](./architecture.md), module layout and three-tier design.
- [init.md](./init.md), `init()` API and module-loader contract.
- [signaturesuite.md](./signaturesuite.md), `SignatureSuite` interface
  plus the `SlhDsa*Suite` and `MlDsa*SlhDsa*Suite` consts.
- [slhdsa_audit.md](./slhdsa_audit.md), implementation audit checklist.
- [mldsa.md](./mldsa.md), the lattice-based post-quantum signature peer.
- [SECURITY.md](../SECURITY.md), PQ-only hybrid threat model and broader
  signature-surface security posture.
