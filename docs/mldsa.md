<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### ML-DSA (Dilithium): Post-Quantum Digital Signatures

Post-quantum digital signatures via ML-DSA (FIPS 204), the NIST-standardized
module-lattice signature scheme.

> ### Table of Contents
> - [Overview](#overview)
> - [Parameter Sets](#parameter-sets)
> - [Init](#init)
> - [MlDsa API](#mldsa-api)
> - [Key Format](#key-format)
> - [Wipe Discipline](#wipe-discipline)
> - [Error Reference](#error-reference)

---

## Overview

ML-DSA (Module-Lattice-Based Digital Signature Algorithm) is a lattice-based
signature scheme standardized by NIST in FIPS 204. It is the post-quantum
counterpart to RSA and ECDSA: existential unforgeability under chosen-message
attack (EUF-CMA) holds even against adversaries with quantum computers. The
hardness assumption is Module-Learning-With-Errors (M-LWE).

This module exposes three classes — `MlDsa44`, `MlDsa65`, and `MlDsa87` —
covering the three FIPS 204 parameter sets. Phase-4 of the v3 release ships
key generation. Signature generation and verification land in subsequent
phases.

Verification against 75 NIST ACVP keyGen-FIPS204 vectors (25 per parameter
set) confirms byte-identical pk/sk output for every seed in the corpus.

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

ML-DSA requires WebAssembly SIMD. `init()` throws a clear error on runtimes
without SIMD support. Every major browser and runtime since 2021 supports it.

---

## MlDsa API

All three classes share the same surface, defined by the `MlDsaBase` parent.
Construction is parameter-less — the parameter set is fixed by the class.

### Constructor

```typescript
new MlDsa44()
new MlDsa65()
new MlDsa87()
```

Throws if `init({ mldsa, sha3 })` has not been called. Cheap — runs a
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

Deterministic key generation — FIPS 204 §6.1 Algorithm 6. Use this when you
must derive a key from a known seed (testing, ACVP, key escrow, deterministic
deployments). Throws `RangeError` if `xi.length !== 32`.

```typescript
const xi = new Uint8Array(32)
crypto.getRandomValues(xi)

const dsa = new MlDsa65()
const { verificationKey, signingKey } = dsa.keygenDerand(xi)
dsa.dispose()
xi.fill(0)  // ξ is the master secret — wipe after use
```

### `dispose(): void`

Wipe all mldsa WASM scratch memory. Idempotent. Safe to call multiple times.
Does not wipe sha3 scratch — every public op already does that under its own
exclusivity guard.

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

## Key Format

`verificationKey` (pk) — FIPS 204 Algorithm 22 (pkEncode):

```
pk = ρ(32) ‖ SimpleBitPack(t₁[0]) ‖ SimpleBitPack(t₁[1]) ‖ … ‖ SimpleBitPack(t₁[k−1])
```

Each packed t₁[i] is `32 · (bitlen(q−1) − d) = 32 · 10 = 320` bytes. Total:
`32 + k · 320`.

`signingKey` (sk) — FIPS 204 Algorithm 24 (skEncode):

```
sk = ρ(32) ‖ K(32) ‖ tr(64)
   ‖ BitPack(s₁[i], η, η)         × ℓ      each = 32 · bitlen(2η)
   ‖ BitPack(s₂[i], η, η)         × k
   ‖ BitPack(t₀[i], 2^(d−1)−1, 2^(d−1)) × k each = 32 · d = 416
```

The signing key includes `tr = H(pk, 64)` precomputed so signing does not
have to re-derive it. Treat the entire sk as private — compromise of any
component (especially ρ′ derivable from ξ, or s₁ derivable from sk) recovers
the full key.

The 32-byte seed ξ is *not* part of the published sk. Storing ξ is sufficient
to reconstruct the full key pair via `keygenDerand` — handle ξ with the same
care as sk.

---

## Wipe Discipline

Every `keygenDerand` call wipes:

- `SEED_OFFSET` — 128 bytes holding ρ ‖ ρ′ ‖ K (highest-severity residual:
  ρ′ expands to s₁/s₂; K is the per-message signing randomness).
- `TR_OFFSET`   — 64 bytes holding tr = H(pk, 64).
- `SK_OFFSET`   — `params.skBytes` holding the encoded sk (already returned
  to the caller; wipe shortens the in-WASM lifetime).
- `POLYVEC_SLOT_0` — s₁ in time-domain (ℓ × 1024 B).
- `POLYVEC_SLOT_1` — s₂ in time-domain (k × 1024 B).
- `POLYVEC_SLOT_2` — t intermediate (k × 1024 B).
- `POLYVEC_SLOT_4` — t₀ secret (k × 1024 B).
- `POLYVEC_SLOT_5` — ŝ₁ in NTT/Montgomery form (ℓ × 1024 B).
- `XOF_PRF_OFFSET` — 8 KiB SHAKE landing zone.

Public regions intentionally left alone: the matrix Â (derived from ρ which
is published in pk), the encoded pk, and t₁ (also published). The sha3
module's STATE/INPUT/OUT regions are wiped before return.

`dispose()` wipes the entire mutable mldsa region — call it when you are
finished with the class.

---

## Error Reference

| Error                                                                                         | Cause                                                                          |
| --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `leviathan-crypto: call init({ mldsa: ... }) before using MlDsa classes`                      | Class constructor invoked before `init({ mldsa, sha3 })`.                      |
| `leviathan-crypto: call init({ sha3: ... }) before using MlDsa classes`                       | Init included `mldsa` but not `sha3`.                                          |
| `RangeError: xi seed must be 32 bytes (got N)`                                                | `keygenDerand(xi)` called with `xi.length !== 32`.                             |
| `leviathan-crypto: another stateful instance is using the 'sha3' WASM module — call dispose()`| A live `SHAKE128` / `SHAKE256` holds the sha3 module; release it first.        |
| `leviathan-crypto: mldsa MATRIX_SLOT too small for {paramSet} (needs N, have M)`              | Internal layout assertion. Indicates a build-time buffer-region misconfiguration. |

---

## Cross-references

- [Architecture](./architecture.md) — module layout and three-tier design.
- [init.md](./init.md) — `init()` API and module-loader contract.
- [asm_mldsa.md](./asm_mldsa.md) — low-level WASM module reference.
- [kyber.md](./kyber.md) — sibling post-quantum module (KEM, not signatures).
