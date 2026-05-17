<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### Merkle Log

Trust-anchored transparency logs. `MerkleVerifier` is the primary normie surface for verifying signed checkpoints, inclusion proofs, and consistency proofs against a fixed log identity. `MerkleLog` is the memory-backed producer companion for in-process logs, fixtures, and demo code. Both are safe-by-default: the dangerous parts of merkle composition (raw trees, custom storage, the wire-format codec) sit behind a divider further down this page.

> ### Table of Contents
> - [Overview](#overview)
> - [Module Init](#module-init)
> - [MerkleVerifier](#merkleverifier)
> - [MerkleLog](#merklelog)
> - [Supported suites](#supported-suites)
> - [Security Notes](#security-notes)
> - [SignedLog](#signedlog)
> - [Sha256Tree and Blake3Tree](#sha256tree-and-blake3tree)
> - [Free-function verifiers](#free-function-verifiers)
> - [Checkpoint and signed-note codec](#checkpoint-and-signed-note-codec)
> - [MerkleStorage and MemoryStorage](#merklestorage-and-memorystorage)
> - [Error Conditions](#error-conditions)
> - [Cross-References](#cross-references)

---

## Overview

A transparency log is an append-only sequence of leaves whose Merkle root is signed at every step. A verifier with a trusted log identity (origin string, public key, signature suite, hash function) can decide three independent questions from short proofs alone:

1. **Checkpoint:** does this signed envelope come from the log I trust?
2. **Inclusion:** is this leaf at this index actually in the tree that envelope commits to?
3. **Consistency:** is the tree at envelope B a superset (an append-only extension) of the tree at envelope A?

The wire format follows the C2SP family: [c2sp.org/tlog-checkpoint](https://c2sp.org/tlog-checkpoint) for the body, [c2sp.org/signed-note](https://c2sp.org/signed-note) for the envelope, [c2sp.org/tlog-cosignature](https://c2sp.org/tlog-cosignature) for the cosignature lines. The Merkle math is RFC 9162 §2.1.1 (tree hash), §2.1.3 (inclusion), and §2.1.4 (consistency).

leviathan ships two hash specialisations and two cosignature suites. Both produce envelopes consumers of any C2SP-conformant log can verify, including [Sigsum](https://sigsum.org/) logs (Ed25519) and any future ML-DSA-44-cosigning log.

| Layer | Choice | When to pick it |
|---|---|---|
| Hashing | `'sha256'` (default) | C2SP-interop, broadly familiar, default for new logs |
| Hashing | `'blake3'` | Native-BLAKE3 stacks; uses BLAKE3 §2.5 tree-mode parent compress directly |
| Suite   | `MlDsa44Suite` (default) | C2SP-recommended PQ default per `c2sp.org/tlog-checkpoint` §Format |
| Suite   | `Ed25519Suite` | Sigsum interop, deterministic per RFC 8032 §5.1.6 |

---

## Module Init

`MerkleLog` and `MerkleVerifier` need three module families: `sha2` (always, for the key-ID SHA-256), the suite's modules, and the hasher's modules. The exact `init({...})` call depends on the combination you pick.

| Hashing | Suite | `init({...})` modules |
|---|---|---|
| `'sha256'` | `Ed25519Suite` | `sha2`, `ed25519` |
| `'sha256'` | `MlDsa44Suite` | `sha2`, `sha3`, `mldsa` |
| `'blake3'` | `Ed25519Suite` | `sha2`, `blake3`, `ed25519` |
| `'blake3'` | `MlDsa44Suite` | `sha2`, `sha3`, `mldsa`, `blake3` |

The class refuses to construct if any required module has not been initialised; `MerkleLogError('module-not-initialized')` names the missing one.

```ts
import { init, MerkleLog, MerkleVerifier, MlDsa44Suite } from 'leviathan-crypto';
import { sha2Wasm }  from 'leviathan-crypto/sha2/embedded';
import { sha3Wasm }  from 'leviathan-crypto/sha3/embedded';
import { mldsaWasm } from 'leviathan-crypto/mldsa/embedded';

await init({ sha2: sha2Wasm, sha3: sha3Wasm, mldsa: mldsaWasm });
```

The `./merkle` subpath (`leviathan-crypto/merkle`) exposes the same surface tree-shakeably when you want to import only the merkle module without pulling the root barrel.

---

## MerkleVerifier

Trust-anchored verifier. Construct it once with the identity of a log you trust, then call the three verify methods as input arrives. Methods always return `boolean`; the class only throws at construction time, on a violated contract.

```ts
import {
  init, MerkleVerifier, MlDsa44Suite, utf8ToBytes,
} from 'leviathan-crypto';
import { sha2Wasm }  from 'leviathan-crypto/sha2/embedded';
import { sha3Wasm }  from 'leviathan-crypto/sha3/embedded';
import { mldsaWasm } from 'leviathan-crypto/mldsa/embedded';

await init({ sha2: sha2Wasm, sha3: sha3Wasm, mldsa: mldsaWasm });

// `pubkey` is the trusted log's public key, obtained out-of-band
// (e.g. baked into the client, distributed via a key-management
// surface). The verifier never fetches it.
const verifier = new MerkleVerifier({
  origin:  'example.com/log42',
  pubkey,
  hashing: 'sha256',
  suite:   MlDsa44Suite,
});

// 1. Verify a signed checkpoint envelope as it arrives.
if (!verifier.verifyCheckpoint(envelopeBytes)) reject('bad checkpoint');

// 2. Verify a leaf's inclusion in the tree that envelope commits to.
const ok = verifier.verifyInclusion({
  envelopeBytes,
  leafBytes,        // raw leaf bytes; verifier re-hashes with `hashing`
  leafIndex,
  proof,            // Uint8Array[] from the log's inclusion-proof endpoint
});
if (!ok) reject('bad inclusion proof');

// 3. Verify that newEnvelope's tree is an append-only extension of oldEnvelope.
const extended = verifier.verifyConsistency({
  oldEnvelopeBytes,
  newEnvelopeBytes,
  proof,
});
if (!extended) reject('log forked or rolled back');
```

### API Reference

| Member | Signature | Description |
|---|---|---|
| `origin` | `string` | The trusted origin captured at construction. Read-only. |
| `pubkey` | `Uint8Array` | A private copy of the trusted pubkey. Read-only. |
| `hasher` | `Hasher` | Resolved `Sha256Hasher` / `Blake3Hasher`. Read-only. |
| `suite` | `SignatureSuite` | The trusted cosignature suite. Read-only. |
| `verifyCheckpoint(envelopeBytes)` | `(Uint8Array) => boolean` | Parses the envelope, checks origin, finds the signature line by keyId, decodes the `timestamped_signature` payload, reconstructs the cosignature signed message per the suite's `messageConstruction`, and runs `suite.verify`. |
| `verifyInclusion(opts)` | `({envelopeBytes, leafBytes, leafIndex, proof}) => boolean` | Runs `verifyCheckpoint` first; on success, hashes `leafBytes` with the configured `Hasher` and calls `verifyInclusionProof` against the body's `treeSize` and `rootHash` per RFC 9162 §2.1.3. |
| `verifyConsistency(opts)` | `({oldEnvelopeBytes, newEnvelopeBytes, proof}) => boolean` | Verifies both envelopes, then calls `verifyConsistencyProof` per RFC 9162 §2.1.4. |

Construction throws `MerkleLogError` with one of these discriminators:

- `'origin-invalid'` if `origin` is empty, contains whitespace, or contains `+`.
- `'pubkey-size'` if `pubkey` is not a `Uint8Array` or its length is not `suite.pkSize`.
- `'unsupported-hashing'` if `hashing` is not `'sha256'` or `'blake3'`.
- `'unsupported-suite'` if `suite.formatEnum` has no entry in the [c2sp.org/tlog-cosignature §Format](https://c2sp.org/tlog-cosignature) algorithm-byte registry.
- `'module-not-initialized'` if any required WASM module has not been `init()`d.

---

## MerkleLog

Memory-backed producer. Build a log from caller-supplied keys with `MerkleLog.create`, or let the class generate a fresh keypair with `MerkleLog.generate` and persist the keys yourself. Hot-path methods (`append`, `head`, `size`, `rootHash`, `inclusionProof`, `consistencyProof`) are synchronous; only `create` and `generate` are async.

### Happy path with the defaults

```ts
import { init, MerkleLog, MerkleVerifier, utf8ToBytes } from 'leviathan-crypto';
import { sha2Wasm }  from 'leviathan-crypto/sha2/embedded';
import { sha3Wasm }  from 'leviathan-crypto/sha3/embedded';
import { mldsaWasm } from 'leviathan-crypto/mldsa/embedded';

await init({ sha2: sha2Wasm, sha3: sha3Wasm, mldsa: mldsaWasm });

// Defaults: hashing = 'sha256', suite = MlDsa44Suite.
const { log, signingKey, pubkey } = await MerkleLog.generate({
  origin: 'example.com/log42',
});

// Persist signingKey + pubkey wherever you keep secrets. The library
// does not touch disk or any network.

try {
  const { leafIndex, inclusionProof } = log.append(utf8ToBytes('leaf-zero'));
  const envelope = log.head();   // signed checkpoint envelope bytes
  // ... publish envelope and proofs to your consumers
} finally {
  log.dispose();   // wipes the signing-key copy
}
```

### Explicit suite for Sigsum interop

```ts
import { init, MerkleLog, Ed25519Suite } from 'leviathan-crypto';
import { sha2Wasm }    from 'leviathan-crypto/sha2/embedded';
import { ed25519Wasm } from 'leviathan-crypto/ed25519/embedded';

await init({ sha2: sha2Wasm, ed25519: ed25519Wasm });

const { log, signingKey, pubkey } = await MerkleLog.generate({
  origin: 'example.com/sigsum-log',
  suite:  Ed25519Suite,
});
```

### API Reference

| Member | Signature | Description |
|---|---|---|
| `MerkleLog.create(opts)` | `static (MerkleLogCreateOpts) => Promise<MerkleLog>` | Validates the suite against the C2SP registry, instantiates the inner tree + `SignedLog`, returns the log. |
| `MerkleLog.generate(opts)` | `static (MerkleLogGenerateOpts) => Promise<{log, signingKey, pubkey}>` | Calls `suite.keygen()` and delegates to `create`. Returns the keypair so the caller can persist it. |
| `origin` | `string` | The origin captured at construction. |
| `hasher` | `Hasher` | Resolved hasher for the tree. |
| `suite` | `SignatureSuite` | The cosignature suite. |
| `append(leafBytes)` | `(Uint8Array) => {leafIndex, leafHash, inclusionProof}` | Append a leaf; returns its index, leaf hash, and inclusion proof against the post-append tree size. |
| `head(opts?)` | `({timestamp?: number}) => Uint8Array` | Emit a signed-note envelope per c2sp.org/signed-note §Format with the current tree size and root hash. Re-signed on every call. Timestamp defaults to `Math.floor(Date.now() / 1000)`. |
| `size()` | `() => number` | Current leaf count. |
| `rootHash()` | `() => Uint8Array` | Current Merkle root hash. |
| `inclusionProof(leafIndex, treeSize?)` | `(number, number?) => Uint8Array[]` | RFC 9162 §2.1.3 inclusion proof. |
| `consistencyProof(oldSize, newSize)` | `(number, number) => Uint8Array[]` | RFC 9162 §2.1.4 consistency proof. |
| `dispose()` | `() => void` | Wipes the stored signing-key copy. Idempotent; subsequent method calls throw. |

`create`'s `signingKey` is copied internally; modifying the caller's view of the buffer after construction does not affect the log. `generate`'s returned `signingKey` and `pubkey` are independent allocations; the log keeps its own copies.

---

## Supported suites

The `suite` option on `MerkleLog` and `MerkleVerifier` must be a leviathan `SignatureSuite` whose `formatEnum` is registered in the [c2sp.org/tlog-cosignature §Format](https://c2sp.org/tlog-cosignature) algorithm-byte registry. As of v3.0.0 the registry covers two suites:

| Suite | leviathan `formatEnum` | C2SP algorithm byte | Notes |
|---|---:|---:|---|
| `Ed25519Suite` | `0x01` | `0x04` | Sigsum interop, deterministic per RFC 8032 §5.1.6 |
| `MlDsa44Suite` | `0x03` | `0x06` | Default, C2SP-recommended PQ, hedged per FIPS 204 §3.4 |

Any other suite (`EcdsaP256Suite`, prehash variants, ML-DSA-65/87, SLH-DSA, hybrids) raises `MerkleLogError('unsupported-suite')` at `MerkleLog.create`, `MerkleLog.generate`, or `MerkleVerifier` constructor time. The registry grows additively: when C2SP registers a new algorithm byte, the table here updates in the same PR that lands the registry extension in `src/ts/merkle/signed-note.ts`. The single source of truth is the `ALGO_REGISTRY` const in `signed-note.ts`; `lookupAlgoEntryByFormatEnum` and `lookupAlgoEntryByByte` expose the registry to power users.

The defaults are intentionally not exported as named constants. `MerkleLog` resolves them internally so call sites stay terse; pinning an explicit value is the way to opt out.

---

## Security Notes

> [!IMPORTANT]
> **Key custody is the caller's responsibility.** `MerkleLog` does not persist keys, send them over the network, or write them to disk. `MerkleLog.generate` returns the freshly generated signing key once; if you lose it, the log can no longer sign new checkpoints under its identity. `dispose()` wipes the log's internal copy but does not touch any copies you held.

> [!IMPORTANT]
> **The verifier hashes leaves itself.** `MerkleVerifier.verifyInclusion` takes raw `leafBytes`, not a pre-computed leaf hash, and runs `hasher.hashLeaf(leafBytes)` internally before calling the proof verifier. This closes the "we trust the proof because we trust the leaf hash the caller passed us" gap. If your transport hands you a leaf hash, you must re-fetch the raw bytes to verify; trusting the hash alone is unsound.

> [!CAUTION]
> **`verifyCheckpoint` runs before proof verification.** `verifyInclusion` and `verifyConsistency` both call `verifyCheckpoint` on the relevant envelope(s) first, and short-circuit to `false` on signature failure. Skipping this ordering (verifying a proof against an unsigned root) lets any party fabricate a root and pair it with a structurally valid proof. The verifier enforces the order; never reimplement this dance manually with the free-function verifiers below unless you understand the bound-to-root-via-signature property.

> [!CAUTION]
> **Suite-selection constraint.** `MerkleLog` and `MerkleVerifier` only accept C2SP-registered cosignature suites (currently Ed25519 and ML-DSA-44). The leviathan signature catalog contains many more suites (`EcdsaP256Suite`, prehash variants, SLH-DSA, hybrids), but none of those have a registered c2sp.org/tlog-cosignature §Format algorithm byte yet, so they cannot produce or verify wire-format-conformant cosignature envelopes. Trying to pass one raises `MerkleLogError('unsupported-suite')` at construction time, before any signing.

> [!CAUTION]
> **`MerkleLog` is memory-backed.** The only storage backend Phase 7 ships is `MemoryStorage`, which keeps every leaf hash and every perfect internal node in a `Map`. Suitable for in-process logs, test fixtures, small embedded uses, and demo code. Real deployments needing file or database storage drop down to the danger-zone surface below: construct `SignedLog<S>` directly with a custom `MerkleStorage` implementation.

> [!CAUTION]
> **`head()` re-signs on every call.** Each invocation produces a fresh signed envelope with the current tree size and root hash, and (by default) the current wall-clock timestamp. For deterministic byte-stable output (tests, KAT vectors), pass `{ timestamp }` explicitly. The c2sp.org/tlog-witness `add-checkpoint` rule mandates a non-zero timestamp on production cosignatures; the API accepts `0` for test reproducibility but real witnesses reject envelopes that carry it.

---

> [!CAUTION]
> # Danger Zone: Raw merkle composition surface
>
> *The classes below give you direct access to unwrapped Merkle trees, signature wrapping, the wire-format codec, and the storage extension point. They exist for protocol implementors, custom-storage deployments, and advanced use cases. If you are building general-purpose transparency logging, stop here and use [`MerkleVerifier`](#merkleverifier) and [`MerkleLog`](#merklelog) above.*
>
> The danger-zone surface inherits the same suite-selection constraint as the normie surface: only suites whose `formatEnum` maps to a C2SP-registered algorithm byte can drive the cosignature wire format. The single source of truth is the `ALGO_REGISTRY` const in `src/ts/merkle/signed-note.ts`; `lookupAlgoEntryByFormatEnum` and `lookupAlgoEntryByByte` expose it to power users.

---

## SignedLog

`SignedLog<S extends SignatureSuite>` ties a `MerkleTree` (Sha256Tree or Blake3Tree), a registered cosignature `SignatureSuite`, and an origin string into one object that produces signed checkpoints and verifies received ones.

```ts
import {
  init, SignedLog, Sha256Tree, MemoryStorage, MlDsa44Suite, utf8ToBytes,
} from 'leviathan-crypto';

const tree = new Sha256Tree(new MemoryStorage());
const log  = new SignedLog({
  tree,
  suite: MlDsa44Suite,
  origin: 'example.com/log42',
  signingKey,
  pubkey,
});

try {
  for (const leafBytes of incoming) tree.append(leafBytes);
  const envelope = log.signCheckpoint({ timestamp: 1740000000 });
  if (!log.verifyCheckpoint(envelope)) throw new Error('verify');
} finally {
  log.dispose();
}
```

### Custom storage backend

`MerkleStorage` is the extension point for file, database, or hybrid backends. Implement the interface and pass an instance to the tree constructor:

```ts
import { MerkleStorage } from 'leviathan-crypto';

class FileStorage implements MerkleStorage {
  // ... implementation, sync everywhere per the merkle layer's invariant
  size(): number { /* ... */ return 0; }
  appendLeaf(leafIndex: number, leafHash: Uint8Array): void { /* ... */ }
  getLeaf(leafIndex: number): Uint8Array { /* ... */ return new Uint8Array(); }
  putNode(level: number, index: number, hash: Uint8Array): void { /* ... */ }
  getNode(level: number, index: number): Uint8Array { /* ... */ return new Uint8Array(); }
  hasNode(level: number, index: number): boolean { /* ... */ return false; }
}

const tree = new Sha256Tree(new FileStorage());
```

If your backend genuinely needs async IO, wrap it externally: pre-load the leaves and nodes synchronously into memory at the boundaries of your operation, then drive the merkle layer.

### API Reference

| Member | Signature | Description |
|---|---|---|
| `new SignedLog(opts)` | `(SignedLogOpts<S>) => SignedLog<S>` | Validates suite registry, copies signing key and pubkey, derives keyId, checks module init readiness. |
| `tree`, `suite`, `origin`, `pubkey`, `wasmModules` | `readonly` | Captured construction inputs. |
| `signCheckpoint(opts?)` | `({timestamp?}) => Uint8Array` | Emit a signed-note envelope per c2sp.org/tlog-cosignature §Format. |
| `verifyCheckpoint(bytes)` | `(Uint8Array) => boolean` | Parses, checks origin and keyId, verifies the cosignature. |
| `parseCheckpoint(bytes)` | `(Uint8Array) => SignedTreeHead` | Structured form: `{checkpoint, signatures, timestamp}`. |
| `append`, `size`, `rootHash`, `getInclusionProof`, `getConsistencyProof` | tree passthroughs | Match `MerkleTree` semantics. |
| `dispose()` | `() => void` | Wipes the signing-key copy. Idempotent. |

`SignedLog` rejects unregistered suites with `SigningError('sig-unsupported-suite')`; the normie classes wrap this with `MerkleLogError('unsupported-suite')` so callers can branch on either.

---

## Sha256Tree and Blake3Tree

Two `MerkleTree` specialisations sharing the same algorithmic core. Both produce 32-byte root hashes and consume / emit 32-byte proof entries; the wire format is identical and only differs in how `hashLeaf` and `hashInternal` are computed.

| Tree | Domain separation | Source |
|---|---|---|
| `Sha256Tree` | RFC 9162 §2.1.1 prefix bytes: `0x00` for leaves, `0x01` for internal nodes | `SHA-256(prefix || data)` |
| `Blake3Tree` | BLAKE3 §2.4 chunk flags (CHUNK_START, CHUNK_END, ROOT) for leaves; BLAKE3 §2.5 parent compress (PARENT flag) for internal nodes | Native BLAKE3 |

### BLAKE3-native tree convention

`Blake3Tree.hashInternal` does **not** stack RFC 6962 prefix bytes on top of BLAKE3. The BLAKE3 spec already provides domain separation via flag bytes; the parent compress is called with `modeFlags = 0` (default mode) and `isRoot = 0` at every internal node, including the top of the tree. Stacking `0x00` / `0x01` prefixes on top of this would be redundant separation and would also discard `compress4` parallelism at the internal-node layer.

### API Reference

| Member | Signature | Description |
|---|---|---|
| `new Sha256Tree(storage)` | `(MerkleStorage) => Sha256Tree` | Constructed empty. `append` is the only mutator. |
| `new Blake3Tree(storage)` | `(MerkleStorage) => Blake3Tree` | Same surface as `Sha256Tree`. |
| `hasher` | `Hasher` | `Sha256Hasher` / `Blake3Hasher` const. |
| `size()` | `() => number` | Leaf count from the storage layer. |
| `rootHash()` | `() => Uint8Array` | Recompute from stored perfect subtrees. |
| `append(leafBytes)` | `(Uint8Array) => {leafIndex, leafHash}` | Hash with `hashLeaf`, persist, propagate completed internal nodes up the right edge. |
| `getInclusionProof(leafIndex, treeSize?)` | `(number, number?) => Uint8Array[]` | RFC 9162 §2.1.3. |
| `getConsistencyProof(oldSize, newSize)` | `(number, number) => Uint8Array[]` | RFC 9162 §2.1.4. |

`Sha256Hasher` and `Blake3Hasher` are exported as standalone `Hasher` consts; pass them directly to the free-function verifiers below if you do not need a stateful tree.

---

## Free-function verifiers

`verifyInclusionProof` and `verifyConsistencyProof` are the thin-verifier path. They take a `Hasher` and the proof bytes, decide RFC 9162 §2.1.3 / §2.1.4 in isolation, and return `boolean`. Use them when you want a checkpoint-less verification (e.g. a witness verifying against a root it already holds), or when you want to integrate the merkle math with a non-leviathan signature stack.

```ts
import { Sha256Hasher, verifyInclusionProof } from 'leviathan-crypto';

const ok = verifyInclusionProof({
  hasher: Sha256Hasher,
  leafHash: hasher.hashLeaf(leafBytes),
  leafIndex,
  treeSize,
  proof,
  rootHash,
});
```

| Function | Behaviour |
|---|---|
| `verifyInclusionProof(input)` | RFC 9162 §2.1.3. Returns `false` on wrong proof length, wrong sibling-hash size, or a reconstructed root that does not match. Throws `RangeError` on contract violations (out-of-range `leafIndex`, `treeSize < 1`, wrong-sized `rootHash`). |
| `verifyConsistencyProof(input)` | RFC 9162 §2.1.4. Returns `false` on wrong proof length or mismatched reconstruction. Throws `RangeError` on `oldSize > newSize` or wrong-sized roots. Empty proof against `oldSize == newSize` requires identical roots. |
| `buildInclusionProof(input)` | RFC 9162 §2.1.3 builder. Takes a `getNode(level, index)` callback so storage backends can drive the same proof builder. |
| `buildConsistencyProof(input)` | RFC 9162 §2.1.4 builder. Returns `[]` for `oldSize == newSize` or `oldSize == 0`. |

The verifier-and-builder pair is hash-agnostic by design; the `Hasher` argument fully determines the domain separation. SHA-256 and BLAKE3 trees produce identical proof wire format and consume the same algorithmic core.

---

## Checkpoint and signed-note codec

Two layered codecs implement the C2SP wire format.

### Checkpoint body

Per [c2sp.org/tlog-checkpoint](https://c2sp.org/tlog-checkpoint) §Note text. Three newline-terminated lines:

```
<origin>\n
<treeSize-decimal>\n
<base64(rootHash)>\n
```

`origin` is non-empty UTF-8, no whitespace, no plus characters. `treeSize` is ASCII decimal with no leading zeroes. `rootHash` uses RFC 4648 §4 standard base64 with padding (not the URL-safe variant). Extension lines are rejected: the cosignature wire format does not commit to them.

```ts
import { serializeCheckpointBody, parseCheckpointBody } from 'leviathan-crypto';

const body = serializeCheckpointBody({ origin, treeSize, rootHash });
const cp   = parseCheckpointBody(body, 32 /* expectedHashLen */);
```

### Signed-note envelope

Per [c2sp.org/signed-note](https://c2sp.org/signed-note) §Format. Body, blank separator line, then one or more `— <name> <base64(keyId||signature)>` signature lines.

```ts
import { emitSignedNote, parseSignedNote } from 'leviathan-crypto';

const envelope = emitSignedNote(body, [signatureLine]);
const env      = parseSignedNote(envelope);
// env.body is the body region (including its trailing newline)
// env.signatures is the parsed signature lines
// env.ignoredCount is the number of signature lines that failed structural validation
```

Structural envelope errors throw `RangeError`; individual signature lines that fail structural validation are silently discarded into `ignoredCount` per the signed-note §Signatures rule "unknown signatures MUST be ignored".

### Cosignature payload codec

Per [c2sp.org/tlog-cosignature](https://c2sp.org/tlog-cosignature) §Format `timestamped_signature` struct:

```
uint64 timestamp_be || signature[N]
```

`N` is the suite's raw signature size (64 for Ed25519, 2420 for ML-DSA-44).

```ts
import {
  emitCosigSignaturePayload, parseCosigSignaturePayload,
} from 'leviathan-crypto';

const payload = emitCosigSignaturePayload(timestamp, sigBytes);
const parsed  = parseCosigSignaturePayload(payload, 64 /* sigSize */);
```

### Signed-message construction

Two constructions dispatch on the algorithm byte registry's `messageConstruction` field:

| `messageConstruction` | Bytes the suite signs | Used by |
|---|---|---|
| `'cosig'` | `cosignature/v1\ntime <decimal>\n<body>` | Ed25519 (algo byte 0x04) |
| `'cosigned-message'` | `cosigned_message` TLS-Presentation struct (label `subtree/v1\n\0`, length-prefixed cosigner_name + log_origin, BE timestamp / start / end, 32-byte hash) | ML-DSA-44 (algo byte 0x06) |

`buildCosigSignedMessage` and `buildCosignedMessage` are exported for code paths that need to reconstruct the signed message manually. `SignedLog`, `MerkleLog`, and `MerkleVerifier` dispatch internally so you never have to choose.

### Key ID derivation

```
keyId = SHA-256(utf8(origin) || 0x0A || algoByte || pubkey)[:4]
```

Per c2sp.org/tlog-cosignature §Format. The key ID is the first 4 bytes of the signature line's base64 payload; the verifier matches it against the keyId derived from the trusted identity to find the right signature line.

```ts
import { deriveKeyId, ALGO_BYTE_MLDSA44_COSIG } from 'leviathan-crypto';

const keyId = deriveKeyId('example.com/log42', ALGO_BYTE_MLDSA44_COSIG, pubkey);
```

---

## MerkleStorage and MemoryStorage

`MerkleStorage` is the per-node persistence interface a `MerkleTree` drives. Two-axis key: `(level, index)`. Level 0 is the leaf row; level `>= 1` stores the hash of a perfect aligned subtree covering `[index * 2^level, (index + 1) * 2^level)`. Roots of partial right-edge subtrees are recomputed on demand by the tree.

```ts
export interface MerkleStorage {
  size(): number;
  appendLeaf(leafIndex: number, leafHash: Uint8Array): void;
  getLeaf(leafIndex: number): Uint8Array;
  putNode(level: number, index: number, hash: Uint8Array): void;
  getNode(level: number, index: number): Uint8Array;
  hasNode(level: number, index: number): boolean;
}
```

Sync everywhere. The merkle layer is synchronous; callers that need async IO wrap externally.

`MemoryStorage` is the only backend leviathan ships. It is suitable for tests, witnesses without persistent storage, and the `MerkleVerifier` short-lived flow. Production logs that need durability implement the interface over a file or database and feed an instance to `Sha256Tree` / `Blake3Tree`.

A bare skeleton for a file backend:

```ts
import { MerkleStorage } from 'leviathan-crypto';

class JsonlFileStorage implements MerkleStorage {
  // Two files: leaves.jsonl (append-only), nodes.jsonl (level/index -> hex).
  // size() reads the leaf-count footer; appendLeaf appends to leaves.jsonl
  // and updates the count; putNode appends to nodes.jsonl with a (level, index)
  // header; getNode / getLeaf / hasNode use an in-memory index map populated
  // at startup. Sync IO via Node's fs.readFileSync / writeFileSync /
  // appendFileSync, which keeps the surface compatible with the merkle
  // layer's sync invariant.
  // ...
}

const tree = new Sha256Tree(new JsonlFileStorage());
```

---

## Error Conditions

The merkle module surfaces three error classes plus standard `RangeError` / `TypeError` for caller-side contract violations.

| Class | Discriminator | Trigger |
|---|---|---|
| `MerkleLogError` | `'origin-invalid'` | `MerkleLog` / `MerkleVerifier` origin empty, has whitespace, or contains `+` |
| `MerkleLogError` | `'pubkey-size'` | pubkey not a `Uint8Array` or length != `suite.pkSize` |
| `MerkleLogError` | `'unsupported-hashing'` | hashing not `'sha256'` or `'blake3'` |
| `MerkleLogError` | `'unsupported-suite'` | suite.formatEnum not in the C2SP cosignature algorithm-byte registry |
| `MerkleLogError` | `'module-not-initialized'` | required WASM module not `init()`d |
| `SigningError` | `'sig-unsupported-suite'` | `SignedLog` with a suite not in the registry (lower-level path) |
| `SigningError` | `'sig-malformed-input'` | `SignedLog.signCheckpoint` got a signature whose size disagrees with the registry entry |
| `MerkleCodecError` | `'timestamp-out-of-range'` | timestamp / start / end not a non-negative safe integer (emit path) |
| `MerkleCodecError` | `'timestamp-exceeds-safe-integer'` | wire u64 timestamp > Number.MAX_SAFE_INTEGER (parse path) |
| `MerkleCodecError` | `'cosig-payload-length-mismatch'` | payload bytes != expected `8 + sigSize` |
| `MerkleCodecError` | `'cosigner-name-length'` | UTF-8 cosigner_name empty or > 255 bytes |
| `MerkleCodecError` | `'log-origin-length'` | UTF-8 log_origin empty or > 255 bytes |
| `MerkleCodecError` | `'cosigned-message-state'` | start != 0 with timestamp != 0 (spec MUST) |
| `RangeError` / `TypeError` | n/a | `parseSignedNote` / `parseCheckpointBody` envelope structural failures; storage layer out-of-order index; proof-builder out-of-range `leafIndex` |

`MerkleVerifier`'s `verifyCheckpoint` / `verifyInclusion` / `verifyConsistency` return `boolean` on every input; they only throw the construction-time `MerkleLogError`s above. `SignedLog.verifyCheckpoint` matches.

---

## Cross-References

| Document | Description |
|---|---|
| [signaturesuite.md](./signaturesuite.md) | Signature suite catalog; `Ed25519Suite` and `MlDsa44Suite` shapes |
| [sha2.md](./sha2.md) | SHA-256 primitive details used by `Sha256Tree` and `deriveKeyId` |
| [blake3.md](./blake3.md) | BLAKE3 primitive details used by `Blake3Tree` |
| [mldsa.md](./mldsa.md) | ML-DSA-44 primitive details used by `MlDsa44Suite` |
| [ed25519.md](./ed25519.md) | Ed25519 primitive details used by `Ed25519Suite` |
| [c2sp.org/tlog-checkpoint](https://c2sp.org/tlog-checkpoint) | Canonical checkpoint body format |
| [c2sp.org/signed-note](https://c2sp.org/signed-note) | Signed-note envelope format |
| [c2sp.org/tlog-cosignature](https://c2sp.org/tlog-cosignature) | Cosignature payload format and algorithm-byte registry |
| [c2sp.org/tlog-witness](https://c2sp.org/tlog-witness) | Witness HTTP protocol (out of leviathan scope as of v3.0.0) |
| [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162) | Certificate Transparency Version 2.0; §2.1.1, §2.1.3, §2.1.4 Merkle math |
| [exports.md](./exports.md) | Full export catalog |
