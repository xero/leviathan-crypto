<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### Ratchet KDF Primitives

KDF primitives from Signal's Sparse Post-Quantum Ratchet (Double Ratchet spec §5 + §7.2): `ratchetInit`, `KDFChain`, `kemRatchetEncap`, `kemRatchetDecap`, `SkippedKeyStore`, and `RatchetKeypair`. Provides key derivation, skipped-key management, and single-use KEM lifecycle.

> ### Table of Contents
> - [Overview](#overview)
> - [Required modules](#required-modules)
> - [A2B/B2A direction split](#a2bb2a-direction-split)
> - [`kemCt` is not optional](#kemct-is-not-optional)
> - [`context` parameter](#context-parameter)
> - [API reference](#api-reference)
> - [Usage example](#usage-example)
> - [Bilateral chain exchange](#bilateral-chain-exchange)
> - [Group and multicast usage](#group-and-multicast-usage)
> - [Error reference](#error-reference)
> - [Demo](#demo)

---

## Overview

The ratchet module implements the KDF layer of the Sparse Post-Quantum Ratchet
protocol. It provides three constructions from Double Ratchet [spec §5 + §7.2](https://signal.org/docs/specifications/doubleratchet/),
all built on HKDF-SHA-256:

- **`KDF_SCKA_INIT`** (`ratchetInit`) — derives the initial root key, send chain
  key, and receive chain key from a shared secret established out-of-band.
- **`KDF_SCKA_CK`** (`KDFChain.step()`) — advances a symmetric chain key and
  derives a per-message key. Stateful, forward-secret.
- **`KDF_SCKA_RK`** (`kemRatchetEncap` / `kemRatchetDecap`) — advances the root
  key using a fresh ML-KEM encapsulation. Provides post-quantum ratchet step
  security.

**What this module does not provide:** a complete ratchet/session
implementation: session state machines, message counters, header format, header
encryption, or epoch lifecycle/orchestration. `SkippedKeyStore` provides
primitive skipped message-key storage, but deciding when to insert, evict, and
consume skipped keys as part of message processing remains an application
concern. The library focuses on key derivation primitives plus the associated
skipped-key storage helper.

---

## Required modules

| Function / Class | Required `init()` modules |
|---|---|
| `ratchetInit`, `KDFChain`, `ratchetReady`, `SkippedKeyStore` | `sha2` |
| `kemRatchetEncap`, `kemRatchetDecap`, `RatchetKeypair` | `sha2`, `kyber`, `sha3` |

```typescript
import { init } from 'leviathan-crypto'
import { sha2Wasm }  from 'leviathan-crypto/sha2/embedded'
import { kyberWasm } from 'leviathan-crypto/kyber/embedded'
import { sha3Wasm }  from 'leviathan-crypto/sha3/embedded'

// For ratchetInit and KDFChain only:
await init({ sha2: sha2Wasm })

// For all functions including KEM ratchet:
await init({ sha2: sha2Wasm, kyber: kyberWasm, sha3: sha3Wasm })
```

---

## A2B/B2A direction split

`sendChainKey` and `recvChainKey` are from the **calling party's perspective**.
Alice's `sendChainKey` is Bob's `recvChainKey` and vice versa. The library
handles this internally: `kemRatchetDecap` swaps the chain key slots via
destructuring rename so the field names are already correct from the decap
side's perspective. Callers must not swap the fields themselves.

```typescript
// Alice — encapsulation side
const alice = kemRatchetEncap(kem, rootKey, bob.encapsulationKey)
// alice.sendChainKey: chain key Alice uses to encrypt messages to Bob
// alice.recvChainKey: chain key Alice uses to decrypt messages from Bob

// Bob — decapsulation side
// ownEk: Bob's encapsulation key (= the peerEk Alice encapsulated against).
// Bound into HKDF info so the chain-key trio on both sides matches.
const bobRaw = kemRatchetDecap(kem, rootKey, dk, alice.kemCt, bob.encapsulationKey)
// bobRaw.sendChainKey corresponds to okm[64:96] — Bob's send direction
// bobRaw.recvChainKey corresponds to okm[32:64] — Bob's receive direction
// The library swaps the slots in kemRatchetDecap so the field names
// are already correct from Bob's perspective:
//   bobRaw.sendChainKey === alice.recvChainKey  ✓
//   bobRaw.recvChainKey === alice.sendChainKey  ✓
```

Both `sendChainKey` and `recvChainKey` are independent 32-byte keys derived
from the same HKDF output but from different offset windows.

---

## `kemCt` is not optional

The `kemCt` field returned by `kemRatchetEncap` **must be transmitted to the peer
in the message header**. The peer cannot call `kemRatchetDecap` without it. A
ratchet step is causally tied to message delivery — it is not instantaneous like
a Diffie-Hellman exchange. Bob can only advance after receiving Alice's `kemCt`.

Both parties must rotate encapsulation keys after each KEM ratchet step so the
next step can proceed.

---

## `context` parameter

All three functions accept an optional `context: Uint8Array` argument. When
provided, its bytes are appended to the HKDF info string before key derivation.

This enables **multi-session key separation**: two sessions initialized with the
same `sk` (or same root key and KEM keys) but different `context` values produce
completely independent key material.

```typescript
const ctx = utf8ToBytes('session-id:abc123')

const alice = ratchetInit(sharedSecret, ctx)
const bob   = ratchetInit(sharedSecret, ctx)
// alice.nextRootKey === bob.nextRootKey  ✓ (same context)

const other = ratchetInit(sharedSecret, utf8ToBytes('session-id:xyz789'))
// other.nextRootKey !== alice.nextRootKey  ✓ (different context)
```

If `context` is omitted, the info string is the protocol identifier alone
(`'leviathan-ratchet-v1 Chain Start'`, `'leviathan-ratchet-v1 Chain Step'`,
or `'leviathan-ratchet-v1 Chain Add Epoch'`).

---

## API reference

### `ratchetInit(sk, context?)`

```typescript
function ratchetInit(sk: Uint8Array, context?: Uint8Array): RatchetInitResult
```

Derives the initial triple of root key and chain keys from a 32-byte shared
secret. Both parties must call this with the same `sk` and `context` to start in
a consistent state.

| Parameter | Type | Description |
|-----------|------|-------------|
| `sk` | `Uint8Array` (32 bytes) | Shared secret established out-of-band |
| `context` | `Uint8Array` (optional) | Domain separation bytes; omit for default |

Returns `RatchetInitResult`:

| Field | Type | Description |
|-------|------|-------------|
| `nextRootKey` | `Uint8Array` (32 bytes) | Initial root key; pass to `kemRatchetEncap`/`Decap` as `rk` |
| `sendChainKey` | `Uint8Array` (32 bytes) | Alice's initial send chain key |
| `recvChainKey` | `Uint8Array` (32 bytes) | Alice's initial receive chain key |

---

### `KDFChain`

Stateful symmetric ratchet chain (spec §5.2, `KDF_SCKA_CK`). Each `step()` call
derives a per-message key and advances the internal chain key.

```typescript
const chain = new KDFChain(sendChainKey)
const msgKey1 = chain.step()  // counter 1
const msgKey2 = chain.step()  // counter 2
chain.dispose()
```

#### `new KDFChain(ck)`

| Parameter | Type | Description |
|-----------|------|-------------|
| `ck` | `Uint8Array` (32 bytes) | Initial chain key; cloned on construction |

#### `chain.step()`

Returns a 32-byte message key for the next message and advances the internal
chain key. The counter is incremented before derivation, so the first call uses
counter value 1.

#### `chain.stepWithCounter()`

```typescript
chain.stepWithCounter(): { key: Uint8Array; counter: number }
```

Returns both the message key and the post-step counter atomically. Eliminates
the two-step `step()` + `.n` read pattern and removes the off-by-one risk from
reading `.n` before stepping.

#### `chain.n`

Returns the counter value used in the most recent `step()` call. Returns `0`
before the first step.

#### `chain.dispose()`

Wipes the internal chain key. Must be called when the chain is no longer needed.
After `dispose()`, `step()` throws.

---

### `SkippedKeyStore`

Manages the MKSKIPPED cache for a single `KDFChain` (DR spec §3.2/§3.5). All
stored keys are 32-byte `Uint8Array` values produced by `KDFChain.step()`.

```typescript
const store = new SkippedKeyStore({ maxCacheSize: 100, maxSkipPerResolve: 50 })
```

#### `new SkippedKeyStore(opts?)`

| Parameter | Type | Description |
|-----------|------|-------------|
| `opts.maxCacheSize` | `number` (optional, default `100`) | Max keys held in the cache. Must be `>= maxSkipPerResolve`. Oldest-first eviction when full. |
| `opts.maxSkipPerResolve` | `number` (optional, default `50`) | Max skip-ahead HKDF derivations per `resolve()` or `advanceToBoundary()` call. Bounds per-message CPU work. |
| `opts.ceiling` | `number` (optional, **deprecated**) | Legacy single-budget option. If provided, sets both `maxCacheSize` and `maxSkipPerResolve` to the same value. |

**Required `init()` modules:** `sha2`

**Split budgets.** `maxCacheSize` bounds memory (how many skipped keys may sit
in RAM waiting for late delivery). `maxSkipPerResolve` bounds per-message CPU
work (how many HKDF-SHA-256 derivations a single malicious/reordered message
can force). Splitting the budgets prevents a single high-counter header from
triggering proportional HKDF work while still allowing a reasonably sized
skipped-key cache.

Constructor throws `RangeError` if either budget is not a safe integer ≥ 1 or
if `maxSkipPerResolve > maxCacheSize`.

#### `store.resolve(chain, counter)`

```typescript
store.resolve(chain: KDFChain, counter: number): ResolveHandle
```

Resolves a message key for the given counter using the provided chain. Returns
a `ResolveHandle` — **not a raw key**. The caller reads `handle.key` for
decryption, then settles via `handle.commit()` on success or
`handle.rollback()` on failure. Double-settle throws. Accessing `.key` after
settling throws. A `FinalizationRegistry` wipes the key as a best-effort
safety net if the handle is GC'd unsettled — but this is not a substitute for
explicit `commit()`/`rollback()` (GC is non-deterministic).

Three delivery paths:

| Condition | Behaviour |
|-----------|-----------|
| `counter === chain.n + 1` (in-order) | Calls `chain.step()`, wraps the key in a handle |
| `counter > chain.n + 1` (skip-ahead) | Steps chain from `chain.n + 1` to `counter − 1`, storing each key with cache enforcement; steps once more for `counter` and wraps that key in a handle without storing it. Throws `RangeError` if the skip distance exceeds `maxSkipPerResolve`. |
| `counter <= chain.n` (past) | Looks up in internal map; if found, removes the entry and wraps the key in a handle. `rollback()` restores it. If not found, throws. |

Cache enforcement evicts the oldest stored key (lowest counter) in O(1) before
inserting when the cache is at capacity. Eviction wipes the evicted buffer.

| Parameter | Type | Description |
|-----------|------|-------------|
| `chain` | `KDFChain` | The chain to step; must be the chain associated with this store |
| `counter` | `number` | The message counter to resolve |

##### `ResolveHandle`

```typescript
interface ResolveHandle {
  readonly key: Uint8Array;
  commit(): void;
  rollback(): void;
}
```

| Member | Description |
|--------|-------------|
| `.key` | 32-byte message key. Read-only while the handle is unsettled. Throws if accessed after `commit()` / `rollback()`. |
| `.commit()` | Success path. Wipes the key buffer in-place and consumes the handle. Subsumes the former post-decrypt `wipe(msgKey)` discipline. |
| `.rollback()` | Failure path. Transfers ownership of the key back to the store under `counter` so a subsequent legitimate delivery at the same counter can retrieve it. Consumes the handle. |

##### Delete-on-retrieval DoS and the rollback mitigation

The previous `resolve()` returned the key directly and deleted it from the
store on retrieval. That created a denial-of-service vector in protocols
without header encryption: an adversary who can inject messages (malicious
relay, MITM against an unauthenticated transport) forges a garbage ciphertext
with a valid counter, the receiver consumes the key trying to decrypt, the
decrypt fails, and the legitimate message that arrives later cannot be
decrypted because its key is gone.

With the handle pattern, the receiver rolls back on auth failure. The key
returns to the store. The legitimate message decrypts fine.

This does not defend against an adversary that can drop messages outright —
that is generic DoS, outside the library's remit. It does defend against the
more surgical "consume this specific counter's key" attack.

##### Idiomatic usage

```typescript
const h = store.resolve(chain, counter);
try {
    const plaintext = Seal.decrypt(cipher, h.key, ciphertext);
    h.commit();
    return plaintext;
} catch (e) {
    h.rollback();
    throw e;
}
```

##### Observable timing: commit vs rollback

`commit()` and `rollback()` do measurably different amounts of work. `commit`
zeros a 32-byte key buffer and consumes the handle. `rollback` may evict an
oldest entry and always inserts into the skipped-key map — a strictly heavier
code path than a single buffer wipe, even on the non-eviction branch. The
idiomatic decrypt pattern calls exactly one of the two depending on whether
the cipher returned plaintext or threw, so a network-layer observer timing the
receiver's per-message processing can distinguish the success path from the
auth-failure path.

The information this leaks is narrower than "decrypt succeeded vs auth failed"
in general. When a legitimate message at a given counter has already been
received and committed, a later tampered copy of the same counter lands on the
past-lookup branch of `resolve()`, finds nothing in the map, and throws before
any cipher work happens at all. This is a distinguishable timing profile in its own
right, but one that signals the legitimate counter has already been processed.
The commit-versus-rollback distinction therefore only applies when the tampered
message arrives before its legitimate counterpart. What the adversary learns in
that case is whether the receiver has yet seen the legitimate counter, a
protocol state that a transport-layer observer typically already has via
message-delivery visibility. The leak is a protocol-state oracle, not a key or
plaintext oracle.

The library does not currently pad the commit path to match rollback's cost.
If your protocol exposes decrypt-path timing to untrusted peers and the
protocol-state leak described above is meaningful at your threat layer, add
padding at the protocol layer. For example, always perform a dummy map touch
before calling `commit`, or schedule `commit()` via `queueMicrotask` to
decouple the observable return timing from the path taken.

#### `store.advanceToBoundary(chain, pn)`

```typescript
store.advanceToBoundary(chain: KDFChain, pn: number): void
```

Steps `chain` from its current position up to and including `pn`, storing each
key. Used at epoch transitions: when a ratchet step arrives with `pn = N`, call
this on the old chain before disposing it so late-arriving old-epoch messages
can still be decrypted. No-op when `pn <= chain.n`. Throws `RangeError` if
the required skip distance exceeds `maxSkipPerResolve`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `chain` | `KDFChain` | The chain to advance |
| `pn` | `number` | Target counter (inclusive) |

#### `store.size`

Returns the current number of stored keys.

#### `store.wipeAll()`

Wipes all stored key buffers and clears the map. Idempotent.

---

### `RatchetKeypair`

Wraps the ek/dk lifecycle for one KEM ratchet step. Enforces single-use:
`decap` may be called exactly once per instance. After `decap`, the dk is wiped
and the instance is consumed.

```typescript
const keypair = new RatchetKeypair(kem)
// share keypair.ek with the encapsulation side
const result = keypair.decap(kem, rk, kemCt)
keypair.dispose()
```

#### `new RatchetKeypair(kem)`

| Parameter | Type | Description |
|-----------|------|-------------|
| `kem` | `MlKemLike` | `MlKem512`, `MlKem768`, or `MlKem1024` instance |

Calls `kem.keygen()` immediately. The `ek` field is available right away.

**Required `init()` modules:** `sha2`, `kyber`, `sha3`

#### `keypair.ek`

```typescript
readonly ek: Uint8Array
```

The encapsulation key to share with peers.

#### `keypair.decap(kem, rk, kemCt, context?)`

```typescript
keypair.decap(
  kem:      MlKemLike,
  rk:       Uint8Array,
  kemCt:    Uint8Array,
  context?: Uint8Array,
): KemDecapResult
```

Decapsulates using the stored dk. The dk is wiped immediately after decap
returns — it never leaves the instance. May only be called once; throws on a
second call.

| Parameter | Type | Description |
|-----------|------|-------------|
| `kem` | `MlKemLike` | Same parameter set used to generate this keypair |
| `rk` | `Uint8Array` (32 bytes) | Current root key |
| `kemCt` | `Uint8Array` | KEM ciphertext received from the encapsulation side |
| `context` | `Uint8Array` (optional) | Domain separation bytes (must match encap side) |

#### `keypair.dispose()`

Wipes the dk if not already wiped by `decap`. Idempotent — safe to call
multiple times or after `decap`.

---

### `kemRatchetEncap(kem, rk, peerEk, context?)`

```typescript
function kemRatchetEncap(
  kem:      MlKemLike,
  rk:       Uint8Array,
  peerEk:   Uint8Array,
  context?: Uint8Array,
): KemEncapResult
```

Encapsulation side of the KEM ratchet step (`KDF_SCKA_RK`, spec §7.2). Generates
a fresh KEM ciphertext, derives the next epoch's keys from the shared secret.

| Parameter | Type | Description |
|-----------|------|-------------|
| `kem` | `MlKemLike` | `MlKem512`, `MlKem768`, or `MlKem1024` instance |
| `rk` | `Uint8Array` (32 bytes) | Current root key (used as HKDF salt) |
| `peerEk` | `Uint8Array` | Peer's encapsulation key |
| `context` | `Uint8Array` (optional) | Domain separation bytes |

Returns `KemEncapResult`:

| Field | Type | Description |
|-------|------|-------------|
| `nextRootKey` | `Uint8Array` (32 bytes) | New root key for the next epoch |
| `sendChainKey` | `Uint8Array` (32 bytes) | Alice's send chain key for this epoch |
| `recvChainKey` | `Uint8Array` (32 bytes) | Alice's receive chain key for this epoch |
| `kemCt` | `Uint8Array` | ML-KEM ciphertext — transmit to peer in message header |

---

### `kemRatchetDecap(kem, rk, dk, kemCt, ownEk, context?)`

```typescript
function kemRatchetDecap(
  kem:      MlKemLike,
  rk:       Uint8Array,
  dk:       Uint8Array,
  kemCt:    Uint8Array,
  ownEk:    Uint8Array,
  context?: Uint8Array,
): KemDecapResult
```

Decapsulation side of the KEM ratchet step. Recovers the shared secret from the
received KEM ciphertext, derives the next epoch's keys. Chain key slots are
swapped relative to the encap side so field names are correct from Bob's
perspective.

> [!IMPORTANT]
> **Breaking change from 1.x:** `kemRatchetDecap` gains a required `ownEk`
> parameter (5th positional arg, before `context`). Pass the local party's
> own encapsulation key — the same public key the encap side targeted as
> `peerEk`. Both sides must bind the identical `(peerEk, kemCt)` pair into
> the HKDF info string; without `ownEk` the decap derivation would diverge
> from the encap side. `RatchetKeypair.decap` threads its stored `ek`
> through automatically, so callers using the high-level helper are
> unaffected.

| Parameter | Type | Description |
|-----------|------|-------------|
| `kem` | `MlKemLike` | Same parameter set used to generate the keypair |
| `rk` | `Uint8Array` (32 bytes) | Current root key |
| `dk` | `Uint8Array` | Bob's decapsulation key |
| `kemCt` | `Uint8Array` | KEM ciphertext received from Alice |
| `ownEk` | `Uint8Array` | Bob's own encapsulation key (the `peerEk` Alice encapsulated against). Bound into HKDF info for defense-in-depth. |
| `context` | `Uint8Array` (optional) | Domain separation bytes (must match encap side) |

**HKDF info binding.** Both sides construct the HKDF info string as

```
INFO_ROOT
  || u32be(|ek|)   || ek       // peerEk on encap, ownEk on decap — same bytes
  || u32be(|ct|)   || kemCt
  || u32be(|ctx|)  || context  // empty length when context omitted
```

so substituting any of `peerEk`, `kemCt`, or `context` in the protocol header
produces a different chain-key trio even if the KEM's shared secret itself
were somehow preserved.

Returns `KemDecapResult`:

| Field | Type | Description |
|-------|------|-------------|
| `nextRootKey` | `Uint8Array` (32 bytes) | New root key (same as Alice's) |
| `sendChainKey` | `Uint8Array` (32 bytes) | Bob's send chain key (= Alice's recvChainKey) |
| `recvChainKey` | `Uint8Array` (32 bytes) | Bob's receive chain key (= Alice's sendChainKey) |

---

### `ratchetReady()`

```typescript
function ratchetReady(): boolean
```

Returns `true` if the `sha2` module has been initialized. Useful for pre-flight
checks.

---

### `RatchetMessageHeader` (type)

```typescript
interface RatchetMessageHeader {
  readonly epoch:   number        // sender's epoch at seal time; starts 0, increments on ratchet step
  readonly counter: number        // KDFChain.n at seal time (post-step value, first message = 1)
  readonly pn?:     number        // previous chain length — present only on the first message of a new epoch
  readonly kemCt?:  Uint8Array    // ML-KEM ciphertext — present only on the first message of a new epoch (encap side)
}
```

Canonical header shape for a ratchet-protected message. All four fields
together encode the information a recipient needs to locate or derive the
correct message key.

| Field | Present | Semantics |
|-------|---------|-----------|
| `epoch` | always | Sender's epoch counter; starts at 0 and increments on each KEM ratchet step |
| `counter` | always | `KDFChain.n` after the step that produced this message's key (first message in an epoch = 1) |
| `pn` | first message of a new epoch only | Previous chain length — `chain.n` just before the ratchet step; used by the recipient to call `advanceToBoundary` on the old chain |
| `kemCt` | first message of a new epoch only (encap side) | KEM ciphertext from `kemRatchetEncap`; the recipient calls `kemRatchetDecap` with this to advance the root key |

`pn` and `kemCt` are absent on every message except the first one of a new
epoch. On that first message, both must be present together.

---

## Usage example

```typescript
import { init, MlKem768, ratchetInit, kemRatchetEncap, kemRatchetDecap, KDFChain } from 'leviathan-crypto'
import { sha2Wasm }  from 'leviathan-crypto/sha2/embedded'
import { kyberWasm } from 'leviathan-crypto/kyber/embedded'
import { sha3Wasm }  from 'leviathan-crypto/sha3/embedded'

// 1. Initialize required modules
await init({ sha2: sha2Wasm, kyber: kyberWasm, sha3: sha3Wasm })

// 2. Create a KEM instance
const kem = new MlKem768()

// 3. Key exchange: Bob generates a keypair and shares the encapsulation key
const { encapsulationKey: bobEk, decapsulationKey: bobDk } = kem.keygen()
// bobEk is transmitted to Alice; bobDk stays with Bob

// 4. Both parties derive initial keys from a shared secret (e.g. from a
//    prior handshake or pre-shared key)
const sharedSecret = new Uint8Array(32)  // from handshake — 32 bytes
const alice = ratchetInit(sharedSecret)
const bob   = ratchetInit(sharedSecret)
// alice.nextRootKey === bob.nextRootKey
// alice.sendChainKey === bob.recvChainKey
// alice.recvChainKey === bob.sendChainKey

// 5. Alice performs a KEM ratchet step, producing kemCt for Bob
const aliceEpoch = kemRatchetEncap(kem, alice.nextRootKey, bobEk)
// aliceEpoch.kemCt is included in Alice's message header to Bob

// 6. Bob decapsulates after receiving kemCt — passes bobEk as ownEk so both
//    sides bind the same (peerEk, kemCt) tuple into HKDF info.
const bobEpoch = kemRatchetDecap(kem, bob.nextRootKey, bobDk, aliceEpoch.kemCt, bobEk)
// bobEpoch.nextRootKey === aliceEpoch.nextRootKey
// bobEpoch.recvChainKey === aliceEpoch.sendChainKey  (Bob receives what Alice sends)
// bobEpoch.sendChainKey === aliceEpoch.recvChainKey  (Bob sends what Alice receives)

// 7. Both parties construct KDFChains and derive per-message keys
const aliceSend = new KDFChain(aliceEpoch.sendChainKey)
const bobRecv   = new KDFChain(bobEpoch.recvChainKey)

const msgKey1 = aliceSend.step()   // Alice encrypts message 1 with this
const recvKey1 = bobRecv.step()    // Bob decrypts message 1 with this
// msgKey1 deepEquals recvKey1 ✓

aliceSend.dispose()
bobRecv.dispose()
kem.dispose()
```

See [docs/ratchet_audit.md](./ratchet_audit.md) for the full security and wipe analysis.

---

## Bilateral chain exchange

`kemRatchetEncap` returns both `sendChainKey` and `recvChainKey`. In a
two-party exchange, both fields are used — neither is wasted. The pattern
below demonstrates a full bilateral epoch step between Alice (encap side)
and Bob (decap side).

```typescript
import {
  init, MlKem768, kemRatchetEncap, kemRatchetDecap,
  KDFChain, RatchetKeypair,
} from 'leviathan-crypto'
import { sha2Wasm }  from 'leviathan-crypto/sha2/embedded'
import { kyberWasm } from 'leviathan-crypto/kyber/embedded'
import { sha3Wasm }  from 'leviathan-crypto/sha3/embedded'
import { wipe } from 'leviathan-crypto'

await init({ sha2: sha2Wasm, kyber: kyberWasm, sha3: sha3Wasm })

const kem = new MlKem768()

// Bob generates his encapsulation keypair and shares the ek
const bobKp = new RatchetKeypair(kem)
// bobKp.ek is transmitted to Alice out-of-band

// Assume both parties hold a shared root key from ratchetInit
const rk = new Uint8Array(32) // from ratchetInit in practice

// ── Alice (encap side) ────────────────────────────────────────────────────────
const alice = kemRatchetEncap(kem, rk, bobKp.ek)
// alice.sendChainKey: Alice uses this to encrypt her chain seed to Bob
// alice.recvChainKey: Alice uses this to decrypt Bob's chain seed response
// alice.nextRootKey:  store this — it is the rk for the next epoch

const nextRk    = alice.nextRootKey  // keep for next kemRatchetEncap call
const aliceSend = new KDFChain(alice.sendChainKey)
const aliceRecv = new KDFChain(alice.recvChainKey)
wipe(alice.sendChainKey)
wipe(alice.recvChainKey)
// alice.kemCt must be transmitted to Bob in the message header

// ── Bob (decap side) ─────────────────────────────────────────────────────────
const bob = bobKp.decap(kem, rk, alice.kemCt)
bobKp.dispose()
// bob.sendChainKey (= alice.recvChainKey): Bob uses this to encrypt to Alice
// bob.recvChainKey (= alice.sendChainKey): Bob uses this to decrypt from Alice
// bob.nextRootKey  (= alice.nextRootKey):  store this for Bob's next epoch

const bobNextRk = bob.nextRootKey  // same value as nextRk
const bobRecv   = new KDFChain(bob.recvChainKey)
const bobSend   = new KDFChain(bob.sendChainKey)
wipe(bob.recvChainKey)
wipe(bob.sendChainKey)

// ── Both derive per-message keys ──────────────────────────────────────────────
const { key: aliceKey1 } = aliceSend.stepWithCounter()
const { key: bobKey1 }   = bobRecv.stepWithCounter()
// aliceKey1 deepEquals bobKey1 ✓  (alice sends, bob receives)

// Session end — wipe all remaining key material
wipe(aliceKey1); wipe(bobKey1)
wipe(nextRk); wipe(bobNextRk)
aliceSend.dispose(); aliceRecv.dispose()
bobRecv.dispose();   bobSend.dispose()
kem.dispose()
```

The key property is `bob.sendChainKey === alice.recvChainKey`. This is why
both fields of the HKDF output are useful: they simultaneously seed the
Alice→Bob and Bob→Alice chains from a single KEM encapsulation.

---

## Group and multicast usage

`kemCt` is **pairwise**: each call to `kemRatchetEncap` uses one recipient's
`ek` and produces a ciphertext only that recipient can decapsulate. A single
`kemCt` cannot be broadcast to multiple recipients.

### N-recipient fan-out

For N recipients, call `kemRatchetEncap` once per recipient's `ek`, producing
N distinct `kemCt` values. Transmit each to its recipient individually.

```typescript
// recipients is an array of { ek: Uint8Array, keypair?: RatchetKeypair }
const rk = currentRootKey  // 32 bytes

const epochResults = recipients.map(r =>
  kemRatchetEncap(kem, rk, r.ek),
)

// Each epochResult has its own kemCt — send epochResults[i].kemCt to recipient i.
// All recipients' nextRootKey values are DIFFERENT — each call uses fresh randomness.
// If shared-root semantics are needed, derive a common root from a side-channel.

for (const result of epochResults) {
  wipe(result.nextRootKey)
  wipe(result.sendChainKey)
  wipe(result.recvChainKey)
}
```

### Sender Keys pattern (shared plaintext chain)

Generate one chain seed once, encrypt it to each recipient using the pairwise
`sendChainKey` from each `kemRatchetEncap` call. All recipients share the same
plaintext chain seed; only the encryption channel is pairwise.

```typescript
const sharedChainSeed = randomBytes(32)

for (let i = 0; i < recipients.length; i++) {
  const r = epochResults[i]
  // Use r.sendChainKey to encrypt sharedChainSeed for recipient i.
  // Transmit (encrypted sharedChainSeed, r.kemCt) to recipient i.
  wipe(r.sendChainKey)
  // r.recvChainKey is unused in broadcast — wipe it
  wipe(r.recvChainKey)
  wipe(r.nextRootKey)
}

// All recipients decrypt using their sendChainKey and derive the shared chain.
const sendChain = new KDFChain(sharedChainSeed)
wipe(sharedChainSeed)
```

### SkippedKeyStore epoch management

`SkippedKeyStore` is scoped to one chain and one epoch. Maintain one store
per sender per epoch:

```typescript
// On epoch transition (new kemCt arrives in header):
// 1. Advance old store to pn (the previous chain length from the header)
oldStore.advanceToBoundary(oldChain, header.pn)
oldChain.dispose()
// Retain oldStore for late-arriving old-epoch messages.

// 2. Create fresh store and chain for the new epoch
const newStore = new SkippedKeyStore()
const newChain = new KDFChain(newEpochChainKey)
wipe(newEpochChainKey)
```

### RatchetKeypair rotation

After each `decap` call, generate a new `RatchetKeypair` and broadcast the
new `ek` to all senders so they use it for the next ratchet step.

```typescript
let myKp = new RatchetKeypair(kem)
// distribute myKp.ek to all senders

// On receiving a KEM ratchet message:
const result = myKp.decap(kem, rk, header.kemCt)
myKp.dispose()

// Generate new keypair immediately
myKp = new RatchetKeypair(kem)
// broadcast myKp.ek to all senders for the next ratchet step
```

---

## Error reference

| Condition | Type | Message |
|-----------|------|---------|
| `ratchetInit` before `init({ sha2 })` | `Error` | `leviathan-crypto: call init({ sha2: ... }) before using ratchetInit` |
| `new KDFChain` before `init({ sha2 })` | `Error` | `leviathan-crypto: call init({ sha2: ... }) before using KDFChain` |
| `kemRatchetEncap` before `init({ sha2 })` | `Error` | `leviathan-crypto: call init({ sha2: ... }) before using kemRatchetEncap` |
| `kemRatchetDecap` before `init({ sha2 })` | `Error` | `leviathan-crypto: call init({ sha2: ... }) before using kemRatchetDecap` |
| `ratchetInit` with `sk.length !== 32` | `RangeError` | `ratchetInit: sk must be 32 bytes` |
| `new KDFChain` with `ck.length !== 32` | `RangeError` | `KDFChain: ck must be 32 bytes` |
| `kemRatchetEncap` with `rk.length !== 32` | `RangeError` | `kemRatchetEncap: rk must be 32 bytes` |
| `kemRatchetDecap` with `rk.length !== 32` | `RangeError` | `kemRatchetDecap: rk must be 32 bytes` |
| `chain.step()` after `chain.dispose()` | `Error` | `KDFChain: instance has been disposed` |
| `chain.step()` when counter is at `Number.MAX_SAFE_INTEGER` | `RangeError` | `KDFChain: counter exceeds maximum safe integer` |
| `store.resolve(chain, counter)` when counter ≤ chain.n and key not in store | `Error` | `SkippedKeyStore: unrecoverable. key for counter ${counter} not found` |
| `store.resolve(chain, counter)` with `counter` not a positive safe integer | `RangeError` | `SkippedKeyStore: invalid counter ${counter}` |
| `store.resolve` when skip distance > `maxSkipPerResolve` | `RangeError` | `SkippedKeyStore: counter ${counter} requires ${n} skip derivations, exceeds maxSkipPerResolve=${N}` |
| `store.advanceToBoundary` when skip distance > `maxSkipPerResolve` | `RangeError` | `SkippedKeyStore: pn=${pn} requires ${n} skip derivations, exceeds maxSkipPerResolve=${N}` |
| `handle.commit()` or `handle.rollback()` called twice | `Error` | `SkippedKeyStore: handle already settled` |
| `handle.key` read after settle | `Error` | `SkippedKeyStore: handle already settled` |
| `new SkippedKeyStore` with `maxSkipPerResolve > maxCacheSize` | `RangeError` | `SkippedKeyStore: maxSkipPerResolve (${s}) must not exceed maxCacheSize (${c})` |
| `new SkippedKeyStore` with invalid `maxCacheSize` | `RangeError` | `SkippedKeyStore: maxCacheSize must be a safe integer >= 1` |
| `new SkippedKeyStore` with invalid `maxSkipPerResolve` | `RangeError` | `SkippedKeyStore: maxSkipPerResolve must be a safe integer >= 1` |
| `keypair.decap(...)` called a second time | `Error` | `RatchetKeypair: already consumed or disposed. generate a new keypair for the next ratchet step` |


---

# Demo

**`COVCOM`** [ [demo](https://leviathan.3xi.club/covcom) · [source](https://github.com/xero/covcom/) · [readme](https://github.com/xero/covcom/blob/master/README.m) ]

A covert communications application for end-to-end encrypted group
conversations, with clients available for both the web and cli, alongside a
containerized dumb server for managing rooms. No secrets or cleartext beyond
the handle you chose to join a room with are ever visible to the server.

Every message is encrypted using XChaCha20-Poly1305 as the core cipher.
The messaging layer use the _Sender Keys_ model. One send chain per participant, not
one per pair, creates O(N) state regardless of room size. Each participant owns one
send chain, a stateful KDFChain that steps forward on every message via
HKDF-SHA-256, producing a unique 32-byte key and wiping the previous chain key.
Message keys are are wiped after use making past keys unrecoverable from the
current state ensuring forward-secrecy.

Epoch transitions use ML-KEM-768. When a ratchet fires, the sender generates a
shared seed, KEM-encapsulates it separately for each peer, and broadcasts the
result. Every peer independently derives the same new chain from that seed. The
KEM ciphertext travels in-band, and the decapsulator's keypair rotates
immediately after use.

---


## Cross-References

| Document | Description |
| -------- | ----------- |
| [index](./README.md) | Project Documentation index |
| [architecture](./architecture.md) | architecture overview, module relationships, buffer layouts, and build pipeline |
| [ratchet_audit](./ratchet_audit.md) | Ratchet KDF implementation audit |
| [kyber](./kyber.md) | ML-KEM key encapsulation (`MlKem512`, `MlKem768`, `MlKem1024`) |
| [sha2](./sha2.md) | HKDF-SHA256 (the underlying primitive) |
| [exports](./exports.md) | full export list |

