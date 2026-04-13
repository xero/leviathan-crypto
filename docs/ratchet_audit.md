# Ratchet KDF Implementation Audit

| Field | Value |
|-------|-------|
| Conducted | Week of 2026-04-13 |
| Target | `leviathan-crypto` ratchet module (`src/ts/ratchet/`) |
| Spec | Signal Double Ratchet §5 + §7.2 (Sparse Post-Quantum Ratchet variant) |
| Underlying primitive | HKDF-SHA-256 (already audited — see [hkdf_audit.md](./hkdf_audit.md)) |

> [!NOTE]
> The ratchet module is a pure TypeScript composition over the already-audited
> HKDF-SHA-256 primitive. No cryptographic computation occurs in the ratchet
> code itself. Only HKDF parameter selection, output slicing, counter encoding,
> and wipe bookkeeping. All three constructions were cross-verified against Python
> `hmac`/`hashlib` via the `scripts/gen-ratchet-vectors.ts` generator.

> ### Table of Contents
> - [Overview](#overview)
> - [KDF Constructions](#kdf-constructions)
>   - [KDF_SCKA_INIT — `ratchetInit`](#kdf_scka_init--ratchetinit)
>   - [KDF_SCKA_CK — `KDFChain.step`](#kdf_scka_ck--kdfchainstep)
>   - [KDF_SCKA_RK — `kemRatchetEncap` / `kemRatchetDecap`](#kdf_scka_rk--kemratchetencap--kemratchetdecap)
> - [Counter Encoding (`KDF_SCKA_CK`)](#counter-encoding-kdf_scka_ck)
> - [Wipe Coverage](#wipe-coverage)
> - [Atomicity](#atomicity)
> - [KEM vs DH Ratchet Semantics](#kem-vs-dh-ratchet-semantics)
> - [Out-of-Scope Items](#out-of-scope-items)
> - [Findings](#findings)

---

## Overview

The ratchet module implements three KDF constructions from the Signal Double Ratchet specification (§5 + §7.2), adapted for ML-KEM. These constructions form the Sparse Post-Quantum Ratchet variant. All three are built on HKDF-SHA-256, using distinct info strings to separate their domains.

**Constructions implemented:**

| Construction | Function / Class | Spec reference |
|---|---|---|
| `KDF_SCKA_INIT` | `ratchetInit` | DR §7.2 |
| `KDF_SCKA_CK` | `KDFChain.step()` | DR §5.2 |
| `KDF_SCKA_RK` | `kemRatchetEncap`, `kemRatchetDecap` | DR §7.2 |

**Out of scope:** session state machine, message counters, header format,
header encryption, and epoch management. These are application concerns. See
[Out-of-Scope Items](#out-of-scope-items). Note that skipped message key
storage IS provided at the library level via `SkippedKeyStore` and its
transactional `ResolveHandle` API — policy above the primitive (retention
windows, persistence, coordination with the surrounding session) remains a
caller concern.

---

## KDF Constructions

### KDF_SCKA_INIT — `ratchetInit`

(`src/ts/ratchet/root-kdf.ts`, `kdfRoot` helper)

Derives the initial root key, send chain key, and receive chain key from a
32-byte shared secret established out-of-band.

**HKDF parameters:**

| Parameter | Value |
|-----------|-------|
| IKM | `sk` — 32-byte shared secret |
| salt | 32 zero bytes (new Uint8Array(32)) |
| info | `'leviathan-ratchet-v1 Chain Start'` (32 bytes UTF-8) [‖ context if provided] |
| L | 96 bytes |

**Output split:**

| Bytes | Field | Description |
|-------|-------|-------------|
| `[0:32]` | `nextRootKey` | Initial root key; passed to `kemRatchetEncap`/`Decap` as `rk` |
| `[32:64]` | `sendChainKey` | Alice's initial send chain key |
| `[64:96]` | `recvChainKey` | Alice's initial receive chain key |

**Info string (UTF-8, no context):**

```
6c 65 76 69 61 74 68 61 6e 2d 72 61 74 63 68 65
74 2d 76 31 20 43 68 61 69 6e 20 53 74 61 72 74
```

(`'leviathan-ratchet-v1 Chain Start'`, 32 bytes)

**Implementation (`kdfRoot` helper, `root-kdf.ts:44–59`):**

The shared helper `kdfRoot(secret, salt, info)` performs all three root KDF
operations. `ratchetInit` passes `salt = new Uint8Array(32)` (32 zero bytes,
the HKDF-SHA-256 default salt for a 32-byte hash output) and `info = INFO_INIT`
(optionally suffixed with `context`). The 96-byte OKM is sliced into three
independent 32-byte keys, then wiped.

Both parties must call `ratchetInit` with the same `sk` and `context` to
arrive at a consistent initial state. The library does not enforce this.

---

### KDF_SCKA_CK — `KDFChain.step`

(`src/ts/ratchet/kdf-chain.ts`, `KDFChain.step()`)

Advances the symmetric chain key and derives a per-message key. Stateful.
Each `step()` call uses the current chain key as IKM and produces a new chain
key plus a message key.

**HKDF parameters:**

| Parameter | Value |
|-----------|-------|
| IKM | `_ck` — current 32-byte chain key |
| salt | 32 zero bytes (module-level `ZERO_SALT` constant) |
| info | `'leviathan-ratchet-v1 Chain Step'` (31 bytes UTF-8) ‖ `N` (8 bytes big-endian uint64) |
| L | 64 bytes |

**Output split:**

| Bytes | Field | Description |
|-------|-------|-------------|
| `[0:32]` | nextChainKey | Replaces `_ck`; used in the next `step()` call |
| `[32:64]` | messageKey | Returned to the caller for encrypting/decrypting message N |

**Info string (UTF-8 prefix, 31 bytes):**

```
6c 65 76 69 61 74 68 61 6e 2d 72 61 74 63 68 65
74 2d 76 31 20 43 68 61 69 6e 20 53 74 65 70
```

(`'leviathan-ratchet-v1 Chain Step'`, 31 bytes), followed by the 8-byte
big-endian encoding of the current counter N. The first `step()` call uses N=1.

**Counter inclusion:** Binding N into the info string makes each step's HKDF
call distinguishable: two chains with the same initial key produce different
message keys at each position (modulo the impossibility of HKDF collisions).
This matches the DR spec's requirement that each step produces independent key
material.

---

### KDF_SCKA_RK — `kemRatchetEncap` / `kemRatchetDecap`

(`src/ts/ratchet/root-kdf.ts`, `kemRatchetEncap` + `kemRatchetDecap`)

KEM ratchet step. The encapsulator generates a fresh KEM ciphertext; both
sides derive the next epoch's root key and chain keys from the resulting shared
secret via HKDF-SHA-256.

**HKDF parameters:**

| Parameter | Value |
|-----------|-------|
| IKM | `sharedSecret` — shared secret from ML-KEM encaps/decaps (32 bytes) |
| salt | `rk` — current 32-byte root key |
| info | `'leviathan-ratchet-v1 Chain Add Epoch'` (36 bytes UTF-8) [‖ context if provided] |
| L | 96 bytes |

**Output split (encap side):**

| Bytes | Field | Description |
|-------|-------|-------------|
| `[0:32]` | `nextRootKey` | New root key for the next KEM ratchet step |
| `[32:64]` | `sendChainKey` | Alice's send chain key for this epoch |
| `[64:96]` | `recvChainKey` | Alice's receive chain key for this epoch |

**Output split (decap side):** Same HKDF output; slots swapped in
`kemRatchetDecap` via destructuring rename so field names are correct from
Bob's perspective (`sendChainKey: recvChainKey, recvChainKey: sendChainKey`).
Bob's `sendChainKey` equals Alice's `recvChainKey` and vice versa.

**Info string (UTF-8, no context):**

```
6c 65 76 69 61 74 68 61 6e 2d 72 61 74 63 68 65
74 2d 76 31 20 43 68 61 69 6e 20 41 64 64 20 45
70 6f 63 68
```

(`'leviathan-ratchet-v1 Chain Add Epoch'`, 36 bytes)

**Role of `rk` as salt:** Using the current root key as the HKDF salt means
the extract phase produces `PRK = HMAC-SHA-256(rk, sharedSecret)`. The root
key is the HMAC key and the shared secret is the HMAC message. This is valid
per RFC 5869 §2.1: salt may be a non-secret value. In the ratchet context, `rk`
is known to both parties at the time of the step; only `sharedSecret` is fresh
randomness from the KEM. The construction chains epochs: each new root key is
derived from the previous root key and the KEM-derived secret, so knowledge of
one epoch does not retroactively expose prior epochs (post-compromise security
relies on the KEM's one-wayness).

---

## Counter Encoding (`KDF_SCKA_CK`)

(`src/ts/ratchet/kdf-chain.ts:57–60`)

```typescript
const ctrBuf = new Uint8Array(8);
const dv     = new DataView(ctrBuf.buffer);
dv.setUint32(0, Math.floor(nextN / 0x100000000), false);
dv.setUint32(4, nextN >>> 0, false);
```

In `step()`, the encoded counter value, `nextN`, represents the post-increment
message number for that step. Consequently, the first successful step encodes
`N = 1`, not `N = 0`. The counter is serialized as a big-endian, unsigned
64-bit integer using two `DataView.setUint32` calls: high word at offset 0 and
the low word at offset 4, both in big-endian format (`false`). This method
generates the standard big-endian uint64 byte sequence without needing `BigInt`.

**Maximum counter value:** `Number.MAX_SAFE_INTEGER` (2^53 − 1 ≈ 9 × 10^15),
determined by JavaScript's safe integer range. A chain advancing at one message
per microsecond would take approximately 285 years to overflow. This is orders
of magnitude above any practical per-chain message limit. A runtime guard
enforces this bound: `step()` throws `RangeError('KDFChain: counter exceeds
maximum safe integer')` if `_n` is already `Number.MAX_SAFE_INTEGER`, because
the next step would exceed the safe integer bound; in that case no increment or
encoding occurs.

**Why not `BigInt`:** N is a public counter value with no secret data. There is
no timing risk in its arithmetic. Two `setUint32` calls produce byte-identical
output to a `setBigUint64` call for all values in the safe integer range, and
avoid introducing a `BigInt` type coercion dependency in a hot path. The
approach is simpler, faster, and equally correct.

---

## Wipe Coverage

All intermediate buffers that hold key material are explicitly wiped. Public
counter values and info strings are not secret and require no wipe.

| Buffer | Containing function | Size | Wipe location |
|--------|---------------------|------|---------------|
| `okm` | `kdfRoot` | 96 bytes | Before return, after slicing all three output keys |
| `okm` | `KDFChain.step()` | 64 bytes | Before return, after slicing nextCk and msgKey |
| `this._ck` (old value) | `KDFChain.step()` | 32 bytes | Before reassignment to nextCk, inside step() |
| `sharedSecret` | `kemRatchetEncap` | 32 bytes | Before return, after kdfRoot completes |
| `sharedSecret` | `kemRatchetDecap` | 32 bytes | Before return, after kdfRoot completes |
| `this._ck` (final value) | `KDFChain.dispose()` | 32 bytes | In dispose() |

**Not wiped (not secret):**

| Buffer | Reason |
|--------|--------|
| `ctrBuf` (counter N) | Public value; no secret data |
| `ZERO_SALT` | Module-level constant; all zero bytes |
| `INFO_INIT`, `INFO_ROOT`, `INFO_CHAIN_BYTES` | Protocol strings; public constants |
| `info` (concatenated with context) | Domain-separation string; public |
| `nextCk` in `step()` | Becomes `this._ck`; wiped on next step() or dispose() |

**HKDF internal buffers:** `HKDF_SHA256.derive()` wipes its internal PRK after
the expand phase completes. The T(i) blocks and concatenation buffers inside
`expand()` are wiped on each iteration. Verified in [hkdf_audit.md §1.5](./hkdf_audit.md#15-buffer-layout-and-memory-safety).

---

## Atomicity

`kemRatchetEncap` and `kemRatchetDecap` each perform a KEM operation followed
immediately by an HKDF derivation. The shared secret produced by the KEM never
leaves either function:

```typescript
// kemRatchetEncap
const { ciphertext: kemCt, sharedSecret } = kem.encapsulate(peerEk);
const { nextRootKey, sendChainKey, recvChainKey } = kdfRoot(sharedSecret, rk, info);
wipe(sharedSecret);
return { nextRootKey, sendChainKey, recvChainKey, kemCt };

// kemRatchetDecap
const sharedSecret = kem.decapsulate(dk, kemCt);
const { nextRootKey, sendChainKey: recvChainKey, recvChainKey: sendChainKey } = kdfRoot(sharedSecret, rk, info);
wipe(sharedSecret);
return { nextRootKey, sendChainKey, recvChainKey };
```

The `sharedSecret` is a local variable. It is passed to `kdfRoot`, which
consumes it synchronously, and then wiped before the function returns. It is
never stored in object state, never yielded across an `await`, and never
returned to the caller. The caller receives only the derived keys.

---

## KEM vs DH Ratchet Semantics

In the classic Double Ratchet, each DH ratchet step is symmetric: once both
parties have exchanged public keys, either party can advance independently. The
ECDH shared secret is derivable by both sides simultaneously.

ML-KEM ratchet advancement is asymmetric:

1. **Encapsulator goes first.** Alice generates `kemCt` via `kem.encapsulate(bobEk)` and derives the new epoch keys. She can proceed immediately.
2. **Decapsulator waits.** Bob cannot advance until he receives `kemCt` from Alice's message header. Only then can he call `kem.decapsulate(bobDk, kemCt)` to recover the shared secret and derive the matching epoch keys.

This causal dependency ties each KEM ratchet step to message delivery. There
is no way for Bob to "pre-advance" independently. A dropped or reordered message
containing `kemCt` stalls Bob's ratchet until it arrives.

Both parties must rotate encapsulation keys after each step: Alice generates a
fresh keypair and shares the new `encapsulationKey`; Bob uses it in the next
`kemRatchetEncap` call. Reuse of an encapsulation key across steps would allow
offline key-recovery if the decapsulation key is later compromised.

---

## Out-of-Scope Items

The ratchet module provides KDF primitives plus local skipped-key storage for
out-of-order message handling. The following remain application concerns and
are not implemented here:

- **Session state machine.** Tracking which ratchet step is current, managing epoch transitions, and coordinating the send/receive state machines for both parties are protocol-layer responsibilities.
- **Header format.** The `kemCt` field must be transmitted to the peer in a message header. The library returns it as a `Uint8Array`; encoding it into a wire format is the application's responsibility.
- **Header encryption.** The Double Ratchet spec describes optional header encryption to conceal ratchet state from observers. This library provides no header encryption.
- **Skipped-key policy and persistence.** The library provides in-memory skipped message key storage via `SkippedKeyStore` (including the transactional `ResolveHandle` API — `commit`/`rollback` — which mitigates the delete-on-retrieval DoS where an adversary injects a garbage ciphertext to consume a specific counter's key before the legitimate message arrives). Applications remain responsible for higher-level policy such as retention windows beyond `maxCacheSize`, persistence across restarts, replay handling at the session layer, and any coordination with their surrounding session model. Header encryption (which would conceal counter metadata from on-path observers and remove the "specific counter" pivot entirely) remains unimplemented and is a protocol-layer concern.
- **Epoch management.** Deciding when to perform a KEM ratchet step (i.e., when to call `kemRatchetEncap` and when to transmit a new encapsulation key) is a protocol-layer policy decision, even if skipped-key caching within an epoch is supported by the library.

---

## Findings

**F-01 — Direction slot alignment in `kemRatchetDecap`**

**Status:** Resolved.

**Description:** The `kdfRoot` helper assigns `okm[32:64]` to `sendChainKey`
and `okm[64:96]` to `recvChainKey`. From the encapsulator's (Alice's) perspective
this is correct: Alice's `sendChainKey` is what she uses to encrypt toward Bob.
However, the decapsulator's (Bob's) send direction is Alice's receive direction.
A naïve port of the same slot assignment would produce `bobResult.sendChainKey
=== aliceResult.sendChainKey`, which is wrong: Bob and Alice would both use the
same key to send, and neither would have the matching key to decrypt the other's
messages.

**Resolution:** `kemRatchetDecap` uses destructuring rename to swap the slots:

```typescript
const { nextRootKey, sendChainKey: recvChainKey, recvChainKey: sendChainKey } =
    kdfRoot(sharedSecret, rk, info);
```

This ensures `bobResult.sendChainKey === aliceResult.recvChainKey` and
`bobResult.recvChainKey === aliceResult.sendChainKey`, which is the correct
A2B/B2A direction mapping. The `kem_ratchet.test.ts` direction symmetry test
verifies this property.

---

**F-02 — `RatchetKeypair.decap` does not wipe `_dk` on throw**

**Status:** Resolved.

**Description:** In the original implementation, `decap()` set `this._used =
true` then called `kemRatchetDecap(kem, rk, this._dk, kemCt, context)`
sequentially, followed by `wipe(this._dk)`. If `kemRatchetDecap` threw (e.g.
from the `rk` length guard — `RangeError: rk must be 32 bytes`), the wipe was
never reached. Because `_used` was already `true`, subsequent calls to
`dispose()` also skipped the wipe via the `if (!this._used)` guard. The
decapsulation key leaked in memory for the lifetime of the instance.

**Resolution:** The `kemRatchetDecap` call was wrapped in `try/finally`:

```typescript
this._used = true;
try {
    return kemRatchetDecap(kem, rk, this._dk, kemCt, context);
} finally {
    wipe(this._dk);
}
```

The `finally` block fires unconditionally — on return and on throw — ensuring
`_dk` is always zeroed. A regression test (`'dk wiped even when decap throws
(bad rk length)'`) covers the throw path.

---

**F-03 — Bilateral exchange example wiped `nextRootKey` before it could be used**

**Status:** Resolved.

**Description:** The bilateral chain exchange example in `docs/ratchet.md`
contained:

```typescript
// alice.nextRootKey becomes the shared root key for the next epoch
wipe(alice.nextRootKey)
```

and the equivalent line for Bob. The comment correctly identified the key as
"the shared root key for the next epoch", then immediately wiped it. Any
consumer implementing a real session from this example would lose their ratchet
root key after the first step and be unable to call `kemRatchetEncap` again in
the next epoch.

**Resolution:** Both lines were replaced with variable assignments that store
the root key for the next epoch:

```typescript
const nextRk    = alice.nextRootKey  // keep for next kemRatchetEncap call
const bobNextRk = bob.nextRootKey    // same value as nextRk
```

The cleanup block at the end of the example was updated to wipe both at session
end: `wipe(nextRk); wipe(bobNextRk)`.

---


## Cross-References

| Document | Description |
| -------- | ----------- |
| [index](./README.md) | Project Documentation index |
| [architecture](./architecture.md) | architecture overview, module relationships, buffer layouts, and build pipeline |
| [ratchet](./ratchet.md) | Ratchet KDF public API reference |
| [hkdf_audit](./hkdf_audit.md) | HKDF-SHA256 audit (underlying primitive) |
| [kyber](./kyber.md) | ML-KEM key encapsulation (KEM ratchet dependency) |
| [sha2](./sha2.md) | HKDF-SHA256 (the underlying primitive) |
| [exports](./exports.md) | full export list |

