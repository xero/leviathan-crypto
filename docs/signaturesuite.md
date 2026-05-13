<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### SignatureSuite

The extension point for the v3 signing layer. `Sign`, `SignStream`, and `VerifyStream` are scheme-agnostic. You provide the signing scheme by passing a `SignatureSuite` object at each call site or to the stream constructors.

---

> ### Table of Contents
> - [Implementations included](#implementations-included)
> - [Pure-mode suites](#pure-mode-suites)
> - [Prehash-mode suites](#prehash-mode-suites)
> - [Wire format](#wire-format)
> - [Interface reference](#interface-reference)
> - [ctx-domain construction](#ctx-domain-construction)
> - [Errors](#errors)
> - [Examples](#examples)
> - [Format byte allocation](#format-byte-allocation)
> - [Custom suites](#custom-suites)
> - [Threat model](#threat-model)
> - [Cross-references](#cross-references)

---

## Implementations included

Phase 1 ships six ML-DSA suites. Three are pure-mode, satisfying `SignatureSuite`; three are prehash-mode, satisfying `StreamableSignatureSuite` and usable with `SignStream` / `VerifyStream`.

Phase 2 adds SLH-DSA (FIPS 205) and the leviathan PQ-only hybrids. Phase 4 adds Ed25519 and Ed25519ph. Phase 5 adds ECDSA-P256. Phase 6 adds the composite classical+PQ hybrids that match `draft-ietf-lamps-pq-composite-sigs`. Phase 7 wires the same `SignatureSuite` shape into the Merkle log signed-tree-head surface. The format-byte allocation at the bottom of this doc reserves a wire byte for every catalog entry, shipped or queued.

---

## Pure-mode suites

Pure-mode suites sign the message bytes directly via FIPS 204 §5.2. They satisfy `SignatureSuite` only, so `SignStream` and `VerifyStream` reject them at the type level.

| Field         | `MlDsa44Suite`         | `MlDsa65Suite`         | `MlDsa87Suite`         |
|---------------|------------------------|------------------------|------------------------|
| `formatEnum`  | `0x03`                 | `0x04`                 | `0x05`                 |
| `formatName`  | `'mldsa44'`            | `'mldsa65'`            | `'mldsa87'`            |
| `ctxDomain`   | `mldsa44-envelope-v3`  | `mldsa65-envelope-v3`  | `mldsa87-envelope-v3`  |
| `pkSize`      | 1312                   | 1952                   | 2592                   |
| `skSize`      | 2560                   | 4032                   | 4896                   |
| `sigSize`     | 2420                   | 3309                   | 4627                   |
| `wasmModules` | `['mldsa', 'sha3']`    | `['mldsa', 'sha3']`    | `['mldsa', 'sha3']`    |

### MlDsa44Suite

NIST security category 2. The smallest ML-DSA parameter set. Pick `MlDsa44Suite` when signature size matters more than long-horizon assurance, for example space-constrained transport. The threat model still covers a CRQC adversary; category 2 is the floor NIST considers acceptable for post-quantum signatures, not a weak choice.

### MlDsa65Suite

NIST security category 3. The general-purpose default. Use `MlDsa65Suite` unless you have a specific reason to pick 44 or 87.

### MlDsa87Suite

NIST security category 5. The largest parameter set, intended for long-lived keys and high-assurance use. Pair `MlDsa87Suite` with key custody designed to outlive the next two decades of cryptanalysis on ML-DSA itself.

See [mldsa.md](./mldsa.md) for the underlying ML-DSA reference, including hedged-versus-deterministic signing and the FIPS 204 validation behaviour.

---

## Prehash-mode suites

Prehash-mode suites wrap HashML-DSA (FIPS 204 §5.4). The suite runs the prehash internally for `sign` / `verify`, and `SignStream` / `VerifyStream` drive it incrementally via the matching `prehashAlgorithm`. Prehash suites satisfy `StreamableSignatureSuite`.

| Field              | `MlDsa44PreHashSuite`              | `MlDsa65PreHashSuite`              | `MlDsa87PreHashSuite`              |
|--------------------|------------------------------------|------------------------------------|------------------------------------|
| `formatEnum`       | `0x13`                             | `0x14`                             | `0x15`                             |
| `formatName`       | `'mldsa44-prehash'`                | `'mldsa65-prehash'`                | `'mldsa87-prehash'`                |
| `ctxDomain`        | `mldsa44-prehash-envelope-v3`      | `mldsa65-prehash-envelope-v3`      | `mldsa87-prehash-envelope-v3`      |
| `pkSize`           | 1312                               | 1952                               | 2592                               |
| `skSize`           | 2560                               | 4032                               | 4896                               |
| `sigSize`          | 2420                               | 3309                               | 4627                               |
| `prehashAlgorithm` | `'sha3-256'`                       | `'sha3-256'`                       | `'sha3-512'`                       |
| `prehashSize`      | 32                                 | 32                                 | 64                                 |
| `wasmModules`      | `['mldsa', 'sha3']`                | `['mldsa', 'sha3']`                | `['mldsa', 'sha3']`                |

### Prehash algorithm choice

FIPS 204 §5.4.1 lists twelve approved prehash functions covering the SHA-2 and SHA-3 families. Phase 1 picks SHA3-256 for ML-DSA-44 and ML-DSA-65, SHA3-512 for ML-DSA-87. Two reasons drive the choice:

- The output size matches the parameter set's λ-derived collision target. ML-DSA-44 / 65 use λ ≥ 128, so a 256-bit digest meets the bound. ML-DSA-87 uses λ = 256, so a 512-bit digest is appropriate.
- Sticking to the SHA-3 family lets prehash suites work with `init({ mldsa, sha3 })` alone. If Phase 1 chose SHA-256 or SHA-512, every prehash consumer would need to add `sha2` to their `init` call. Phase 4 onwards may add SHA-2-prehash variants for protocols that mandate them.

The mldsa primitive supports all twelve §5.4.1 algorithms via `MlDsaBase.signHash` / `verifyHash`; see [mldsa.md](./mldsa.md#pre-hash-algorithms). The Phase 1 prehash suites pin the choice for byte-stable wire interop. Future phases that need a different prehash get their own format byte rather than reusing one of the bytes above.

### MlDsa44PreHashSuite, MlDsa65PreHashSuite, MlDsa87PreHashSuite

Use these when the application cannot buffer the full message before signing, or when the consumer is a `SignStream` over chunked input. The wire is byte-identical to a `Sign.sign` call with the same parameter set and prehash, so a receiver can use either `Sign.verify` or `VerifyStream` interchangeably.

> [!IMPORTANT]
> Pure-mode and prehash-mode signatures are not interchangeable, even on the same key. HashML-DSA's M' uses a different domain-separator byte from pure ML-DSA (FIPS 204 §3.6.4). The wire format encodes which mode produced the signature via `formatEnum`; the receiver must match the suite the sender used.

---

## Wire format

### Attached envelope

`Sign.sign` and `SignStream` emit the same byte sequence. The layout is one suite byte, one ctx length byte, the user ctx bytes, the payload, and finally the signature.

```
byte  0                : suite_byte    (u8, suite.formatEnum)
byte  1                : ctx_len       (u8, 0..255)
bytes 2 .. 2+ctx_len   : ctx           (raw user_ctx, no domain prefix)
bytes ... payload_end  : payload       (length deduced from blob length)
bytes payload_end .. N : sig           (exactly suite.sigSize bytes)
```

Total size is `2 + ctx_len + payload_len + suite.sigSize`. There is no length prefix on `sig` because every catalog suite has a fixed `sigSize`. There is no length prefix on `payload` because it is deduced as `blob.length - 2 - ctx_len - suite.sigSize`.

> [!NOTE]
> The wire carries the raw `user_ctx`, not the `effective_ctx` the suite builds internally. The receiver passes its own `ctx` to `Sign.verify` or `VerifyStream`, the envelope layer compares it against the wire ctx in constant time, and the suite reconstructs `effective_ctx` for the underlying primitive. The wire bytes do not encode the suite's `ctxDomain`.

### Parser flow (attached verify)

1. Validate `blob.length ≥ 2 + suite.sigSize`. Fail with `sig-blob-too-short`.
2. Read `suite_byte`. Compare against `suite.formatEnum`. Fail with `sig-suite-mismatch`.
3. Read `ctx_len`.
4. Validate `2 + ctx_len ≤ blob.length - suite.sigSize`. Fail with `sig-ctx-overflow`.
5. Slice `ctx`, `payload`, and `sig` from the known offsets.
6. Compare caller `ctx` against wire `ctx` in constant time. Fail with `sig-ctx-mismatch`.
7. Call `suite.verify(pk, payload, sig, wire_ctx)`. A `false` return becomes `verify-failed`.
8. Return `payload` on success.

`sig-suite-unknown` is reserved for a future routing API that resolves the suite from the wire byte; Phase 1 callers always pass the suite explicitly, so the discriminator never fires here.

### Detached signature

`Sign.signDetached` returns raw signature bytes (`Uint8Array(suite.sigSize)`). No header, no metadata. The caller manages the `(suite, pk, msg, sig, ctx)` tuple out of band. Use detached signatures when the message is transported separately, or when the wire format must match an external standard (CMS, COSE, JWS) that frames the signature itself.

---

## Interface reference

### `SignatureSuite`

| Field         | Type                | Description |
|---------------|---------------------|-------------|
| `formatEnum`  | `number`            | Wire format byte. Bits 0-3 select within category, bits 4-5 select category (`0x0X` pure, `0x1X` prehash, `0x2X` classical+PQ hybrid, `0x3X` PQ-only hybrid), bits 6-7 reserved. |
| `formatName`  | `string`            | Human label, for example `'mldsa65'` or `'mldsa65-prehash'`. |
| `ctxDomain`   | `string`            | Built-in domain separator concatenated with the user ctx before reaching the underlying primitive. Capped at 32 bytes (UTF-8) at factory construction. |
| `pkSize`      | `number`            | Public key size in bytes. |
| `skSize`      | `number`            | Secret key size in bytes. |
| `sigSize`     | `number`            | Signature size in bytes. Fixed per suite. |
| `wasmModules` | `readonly string[]` | WASM modules this suite needs initialized via `init()`. |

| Method                          | Description |
|---------------------------------|-------------|
| `sign(sk, msg, ctx)`            | Return raw signature bytes. Throws `SigningError` on contract violations (wrong-size key, ctx too long). |
| `verify(pk, msg, sig, ctx)`     | Return boolean for every signature outcome, including malformed encodings. Throws `SigningError` only on contract violations. |
| `keygen()`                      | Return `{ pk, sk }`. Hedged keygen via `crypto.getRandomValues`. |

### `StreamableSignatureSuite extends SignatureSuite`

Adds the digest-input methods `SignStream` / `VerifyStream` call after running the prehash internally.

| Field              | Type                | Description |
|--------------------|---------------------|-------------|
| `prehashAlgorithm` | `PrehashAlgorithm`  | Prehash identifier, pinned at suite construction. |
| `prehashSize`      | `number`            | Digest size in bytes for `prehashAlgorithm`. |

| Method                                       | Description |
|----------------------------------------------|-------------|
| `signPrehashed(sk, digest, ctx)`             | Sign a precomputed digest. Throws `SigningError('sig-malformed-input')` if `digest.length !== prehashSize`. |
| `verifyPrehashed(pk, digest, sig, ctx)`      | Verify a precomputed-digest signature. Returns `false` on wrong-length digest. Throws `SigningError` only on contract violations. |

### `PrehashAlgorithm`

```typescript
type PrehashAlgorithm =
  | 'sha-256'
  | 'sha-512'
  | 'sha3-256'
  | 'sha3-512'
  | 'shake-128'
  | 'shake-256'
```

The Phase 1 prehash suites use `'sha3-256'` and `'sha3-512'`. The remaining values are reserved for future phases.

### Locked semantics

- `ctx` is required on every call. Pass an empty `Uint8Array` if you have no context, never `undefined` and never a missing positional argument. The wire format ctx slot is `Uint8Array(0)` in that case.
- `verify` returns boolean for every signature outcome: wrong sig, malformed hint encoding, wrong-length pk or sig per FIPS 204 §3.6.2. Contract violations such as `user_ctx.length > 200` throw `SigningError`.
- `keygen` returns `{ pk, sk }` regardless of how the underlying primitive labels its keys.
- All `SignatureSuite` fields are `readonly`.

---

## ctx-domain construction

Every suite has a `ctxDomain` string baked into its factory call. The suite combines the suite domain and the caller's user ctx into the `effective_ctx` it passes to the underlying primitive:

```
effective_ctx = [domain_len: u8] [domain_bytes] [user_ctx_len: u8] [user_ctx_bytes]
```

Both fields are length-prefixed by a single byte. The length-prefix layout means a colliding suite cannot construct a different `(domain, user_ctx)` pair that produces the same `effective_ctx`.

Caps:

- `ctxDomain ≤ 32 bytes` after UTF-8 encoding. Validated at factory-construction time; passing a longer string throws a plain `Error` because that is a developer-time mistake, not a caller mistake.
- `user_ctx ≤ 200 bytes` per call. Validated each time. Throws `SigningError('sig-ctx-too-long')`. The cap leaves headroom under FIPS 204's 255-byte ctx limit even after the length prefixes.

The wire `ctx_len` field is `u8`, so `user_ctx` is additionally capped at 255 on the wire. Phase 1 uses the smaller 200-byte cap for ergonomic headroom under the FIPS 204 limit.

### Naming convention

Suite `ctxDomain` values follow a simple pattern.

- Pure-mode suites: `{scheme}-envelope-v3`.
- Prehash-mode suites: `{scheme}-prehash-envelope-v3`.

Phase 2 hybrid suites use `{outer}-{inner}-envelope-v3`; see the format byte allocation table for the full list.

---

## Errors

Every signing-layer failure throws `SigningError(discriminator, message?)`. The discriminator is the stable, machine-readable identifier; the message is a human-readable string with context. The discriminators below are organized by layer.

| Discriminator           | Layer             | Trigger |
|-------------------------|-------------------|---------|
| `sig-key-size`          | suite             | Wrong-length sk or pk for the suite. |
| `sig-ctx-too-long`      | suite             | `user_ctx` exceeds 200 bytes. |
| `sig-malformed-input`   | suite             | Primitive validation failure, for example a wrong-length digest in `signPrehashed`. |
| `sig-blob-too-short`    | envelope          | `Sign.verify` blob shorter than `2 + suite.sigSize`. |
| `sig-suite-unknown`     | envelope          | Wire `suite_byte` is not in the catalog. Reserved; Phase 1 callers pass the suite explicitly, so this discriminator does not fire today. |
| `sig-suite-mismatch`    | envelope, stream  | Wire `suite_byte` does not equal the caller's `suite.formatEnum`. |
| `sig-ctx-overflow`      | envelope          | Wire `ctx_len` pushes past the signature boundary. |
| `sig-ctx-mismatch`      | envelope, stream  | Caller `ctx` does not equal wire `ctx`. Constant-time compared. |
| `verify-failed`         | envelope          | `suite.verify` returned false during envelope verify. |
| `sig-stream-finalized`  | stream            | `update()` called after `finalize()`. |
| `sig-stream-disposed`   | stream            | Any operation on a disposed stream. |

`VerifyStream.finalize` also throws `verify-failed` and `sig-blob-too-short` (the latter when finalize fires before enough bytes arrived for a full signature).

---

## Examples

Every example below imports from the public package surface and shows the matching `init` call upfront.

### `Sign.sign` and `Sign.verify` (single-shot, attached)

```typescript
import {
  init,
  Sign,
  MlDsa65Suite,
} from 'leviathan-crypto'
import { mldsaWasm } from 'leviathan-crypto/mldsa/embedded'
import { sha3Wasm }  from 'leviathan-crypto/sha3/embedded'

await init({ mldsa: mldsaWasm, sha3: sha3Wasm })

const { pk, sk } = MlDsa65Suite.keygen()
const msg = new TextEncoder().encode('hello world')
const ctx = new TextEncoder().encode('myapp/v1')

const blob    = Sign.sign(MlDsa65Suite, sk, msg, ctx)
const payload = Sign.verify(MlDsa65Suite, pk, blob, ctx)
// payload is the recovered msg bytes
```

### `Sign.signDetached` and `Sign.verifyDetached`

```typescript
import {
  init,
  Sign,
  MlDsa65Suite,
} from 'leviathan-crypto'
import { mldsaWasm } from 'leviathan-crypto/mldsa/embedded'
import { sha3Wasm }  from 'leviathan-crypto/sha3/embedded'

await init({ mldsa: mldsaWasm, sha3: sha3Wasm })

const { pk, sk } = MlDsa65Suite.keygen()
const msg = new TextEncoder().encode('hello world')
const ctx = new TextEncoder().encode('myapp/v1')

const sig = Sign.signDetached(MlDsa65Suite, sk, msg, ctx)
const ok  = Sign.verifyDetached(MlDsa65Suite, pk, msg, sig, ctx)
// ok === true; sig is exactly MlDsa65Suite.sigSize bytes
```

### `SignStream` over chunked input

```typescript
import {
  init,
  SignStream,
  MlDsa65PreHashSuite,
} from 'leviathan-crypto'
import { mldsaWasm } from 'leviathan-crypto/mldsa/embedded'
import { sha3Wasm }  from 'leviathan-crypto/sha3/embedded'

await init({ mldsa: mldsaWasm, sha3: sha3Wasm })

const { pk, sk } = MlDsa65PreHashSuite.keygen()
const ctx = new TextEncoder().encode('myapp/v1')

const signer   = new SignStream(MlDsa65PreHashSuite, sk, ctx)
const preamble = signer.preamble                       // write to output first
signer.update(chunk1)
signer.update(chunk2)
const sig = signer.finalize()                          // write to output last
// wire output is preamble + chunk1 + chunk2 + sig
signer.dispose()
```

### `VerifyStream` over the same wire

```typescript
import {
  init,
  VerifyStream,
  MlDsa65PreHashSuite,
} from 'leviathan-crypto'
import { mldsaWasm } from 'leviathan-crypto/mldsa/embedded'
import { sha3Wasm }  from 'leviathan-crypto/sha3/embedded'

await init({ mldsa: mldsaWasm, sha3: sha3Wasm })

// pk and ctx must match the SignStream side
const verifier = new VerifyStream(MlDsa65PreHashSuite, pk, ctx)
verifier.update(preamble)
verifier.update(chunk1)
verifier.update(chunk2)
verifier.update(sig)
const payload = verifier.finalize()                    // throws SigningError on bad sig
verifier.dispose()
```

`update` accepts arbitrarily-sized chunks; the stream parses byte-by-byte through the header and slides an internal sigSize-byte window through the data. A receiver that doesn't yet know which suite produced the wire bytes can call `Sign.peek` (next example) before constructing `VerifyStream`.

### `Sign.peek` for routing

```typescript
import {
  init,
  Sign,
  MlDsa65Suite,
} from 'leviathan-crypto'
import { mldsaWasm } from 'leviathan-crypto/mldsa/embedded'
import { sha3Wasm }  from 'leviathan-crypto/sha3/embedded'

await init({ mldsa: mldsaWasm, sha3: sha3Wasm })

// blob is an attached envelope produced by Sign.sign or SignStream.
// peek validates structural shape only; it does NOT verify the signature
// and does NOT compare ctx.
const meta = Sign.peek(blob, MlDsa65Suite)
// meta.suiteByte      : number, the wire suite byte
// meta.ctx            : Uint8Array, the wire ctx
// meta.payloadOffset  : number, byte offset of the payload start
// meta.payloadLength  : number, payload length in bytes
// meta.sigOffset      : number, byte offset of the signature start
```

Use `peek` to extract metadata for routing or logging without paying the verify cost. Always follow up with `Sign.verify` (or `VerifyStream`) before trusting the payload.

---

## Format byte allocation

The full 22-entry catalog. Phase 1 rows are shipped; later phases are queued. Phase numbers refer to the v3 phase plan in the repo's planning docs.

| Byte | Suite                       | Mode    | Prehash               | ctxDomain                          | Phase | Status   |
|------|-----------------------------|---------|-----------------------|------------------------------------|-------|----------|
| 0x01 | `Ed25519Suite`              | pure    | -                     | `ed25519-envelope-v3`              | 4     | queued   |
| 0x02 | `EcdsaP256Suite`            | single  | SHA-256               | `ecdsa-p256-envelope-v3`           | 5     | queued   |
| 0x03 | `MlDsa44Suite`              | pure    | -                     | `mldsa44-envelope-v3`              | 1     | shipped  |
| 0x04 | `MlDsa65Suite`              | pure    | -                     | `mldsa65-envelope-v3`              | 1     | shipped  |
| 0x05 | `MlDsa87Suite`              | pure    | -                     | `mldsa87-envelope-v3`              | 1     | shipped  |
| 0x06 | `SlhDsa128fSuite`           | pure    | -                     | `slhdsa128f-envelope-v3`           | 2     | queued   |
| 0x07 | `SlhDsa192fSuite`           | pure    | -                     | `slhdsa192f-envelope-v3`           | 2     | queued   |
| 0x08 | `SlhDsa256fSuite`           | pure    | -                     | `slhdsa256f-envelope-v3`           | 2     | queued   |
| 0x11 | `Ed25519PreHashSuite`       | prehash | SHA-512 (Ed25519ph)   | `ed25519-prehash-envelope-v3`      | 4     | queued   |
| 0x13 | `MlDsa44PreHashSuite`       | prehash | SHA3-256              | `mldsa44-prehash-envelope-v3`      | 1     | shipped  |
| 0x14 | `MlDsa65PreHashSuite`       | prehash | SHA3-256              | `mldsa65-prehash-envelope-v3`      | 1     | shipped  |
| 0x15 | `MlDsa87PreHashSuite`       | prehash | SHA3-512              | `mldsa87-prehash-envelope-v3`      | 1     | shipped  |
| 0x16 | `SlhDsa128fPreHashSuite`    | prehash | SHAKE-128             | `slhdsa128f-prehash-envelope-v3`   | 2     | queued   |
| 0x17 | `SlhDsa192fPreHashSuite`    | prehash | SHAKE-128             | `slhdsa192f-prehash-envelope-v3`   | 2     | queued   |
| 0x18 | `SlhDsa256fPreHashSuite`    | prehash | SHAKE-256             | `slhdsa256f-prehash-envelope-v3`   | 2     | queued   |
| 0x20 | `MlDsa44Ed25519Suite`       | hybrid  | SHA-512               | `mldsa44-ed25519-envelope-v3`      | 6     | queued   |
| 0x21 | `MlDsa65Ed25519Suite`       | hybrid  | SHA-512               | `mldsa65-ed25519-envelope-v3`      | 6     | queued   |
| 0x22 | `MlDsa44EcdsaP256Suite`     | hybrid  | SHA-256               | `mldsa44-ecdsa-p256-envelope-v3`   | 6     | queued   |
| 0x23 | `MlDsa65EcdsaP256Suite`     | hybrid  | SHA-512               | `mldsa65-ecdsa-p256-envelope-v3`   | 6     | queued   |
| 0x30 | `MlDsa44SlhDsa128fSuite`    | hybrid  | SHAKE-128             | `mldsa44-slhdsa128f-envelope-v3`   | 2     | queued   |
| 0x31 | `MlDsa65SlhDsa192fSuite`    | hybrid  | SHAKE-256             | `mldsa65-slhdsa192f-envelope-v3`   | 2     | queued   |
| 0x32 | `MlDsa87SlhDsa256fSuite`    | hybrid  | SHAKE-256             | `mldsa87-slhdsa256f-envelope-v3`   | 2     | queued   |

22 of 64 slots used. Reserved capacity covers Ed448, ECDSA-P384, brainpool curves, FROST suites, ML-DSA-87 classical hybrids, and threshold variants.

The classical+PQ hybrid bytes (`0x20-0x23`) follow the composite-sigs draft `HashMLDSA{44,65}-{Ed25519,ECDSA-P256}-{SHA256,SHA512}` encoding. The PQ-only hybrid bytes (`0x30-0x32`) are leviathan-flavored; the composite encoding spec lands in this document during Phase 2.

---

## Custom suites

`SignatureSuite` is a TypeScript interface, not a sealed class. A consumer can satisfy the interface and pass a custom suite to `Sign`, `SignStream`, and `VerifyStream`. The catalog format bytes are reserved by the library, so a custom suite must pick a `formatEnum` outside the allocated range. Phase 1 does not reserve a specific custom-suite range; if you need one, raise an issue.

Custom suites do not get the factory helpers the in-tree suites use. You are responsible for the per-call WASM lifecycle, the `ctxDomain` cap, the `effective_ctx` construction, and the per-method wipe discipline. Read `src/ts/sign/suites/mldsa.ts` before writing one; the mldsa-suites factory captures every invariant the in-tree suites satisfy.

---

## Threat model

### Pure versus prehash

Pure-mode suites bind the full message bytes inside FIPS 204's M' construction (`M' = 0x00 ‖ |ctx| ‖ ctx ‖ M`). Prehash-mode suites compose with FIPS 204 §5.4 HashML-DSA, which substitutes `M' = 0x01 ‖ |ctx| ‖ ctx ‖ OID(ph) ‖ Hash(M, ph)`. The domain-separator byte differs (`0x00` vs `0x01`), so a signature produced in one mode never verifies in the other on the same key.

Pure mode offers the larger collision-resistance margin because the signature binds the message bytes themselves. Prehash mode is necessary when the application cannot buffer `M`; the streaming layer in this library uses it for that reason.

### Classical+PQ hybrid (Phase 6, `0x2X`)

Classical+PQ hybrids defend against the case where the PQ assumption (M-LWE for ML-DSA) is broken before a CRQC arrives. The classical half (Ed25519 or ECDSA-P256) keeps signatures unforgeable in that world. These hybrids do not defend against a CRQC adversary; the classical half falls to Shor's algorithm. Ship them when you need ecosystem interop or PKI migration, not when the threat model assumes a future CRQC.

### PQ-only hybrid (Phase 2, `0x3X`)

PQ-only hybrids defend against the case where one PQ family is broken while the other holds. ML-DSA pairs with SLH-DSA, which rests on a different cryptanalytic foundation (hash-based, no lattice assumption). Neither half falls to Shor's algorithm; Grover's quadratic speedup only halves SLH-DSA's bit security, well above its design margin. Pick PQ-only hybrids when you need "this signature must verify in 2050."

The library carries both hybrid families because consumer threat models differ. Classical hybrids serve adoption and interop; PQ-only hybrids serve long-horizon assurance.

---

## Cross-references

| Document | Description |
|----------|-------------|
| [README](./README.md) | Documentation index |
| [architecture](./architecture.md) | Module overview, build pipeline, and three-tier design |
| [ciphersuite](./ciphersuite.md) | Symmetric / AEAD counterpart to this document |
| [mldsa](./mldsa.md) | Underlying ML-DSA reference, including `signHashPrehashed` and the FIPS 204 §5.4 prehash family |
| [aead](./aead.md) | `Seal`, `SealStream`, `OpenStream` (parallel encryption surface) |
| [errors](./exports.md) | `SigningError` and `AuthenticationError` export reference |
| [types](./types.md) | TypeScript interfaces |

External references:

- FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA), 2024.
- FIPS 205: Stateless Hash-Based Digital Signature Standard (SLH-DSA), 2024.
- FIPS 186-5: Digital Signature Standard (DSS), 2023 (ECDSA).
- RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA).
- `draft-ietf-lamps-pq-composite-sigs`: Composite ML-DSA hybrid encodings.
