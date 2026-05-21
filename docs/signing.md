<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### Digital Signatures

Scheme-agnostic digital signatures for any scale. One-shot with `Sign`, chunked with `SignStream` and `VerifyStream`. All three share an envelope wire format and accept any `SignatureSuite`.

> ### Table of Contents
> - [Overview](#overview)
> - [Security Model](#security-model)
> - [Wire Format](#wire-format)
> - [API Reference](#api-reference)

---

## Overview

Digital signatures in leviathan-crypto center on three classes: `Sign`, `SignStream`, and `VerifyStream`. All are scheme-agnostic. Pass a `SignatureSuite` object at the call site and they handle context binding, the M' construction, and authentication automatically.

These three form a natural progression by use case. Use `Sign` for messages that fit in memory. Use `SignStream` and `VerifyStream` for messages arriving in chunks or too large to buffer. `Sign` and `SignStream` share the same attached envelope, so a `VerifyStream` can verify a `Sign.sign` blob and vice versa.

leviathan-crypto ships 22 signature suites grouped into six families:

| Family | Members | Modules |
|---|---|---|
| ML-DSA (FIPS 204) | `MlDsa{44,65,87}Suite` plus `MlDsa{44,65,87}PreHashSuite` | `mldsa`, `sha3` |
| SLH-DSA (FIPS 205) | `SlhDsa{128f,192f,256f}Suite` plus `SlhDsa{128f,192f,256f}PreHashSuite` | `slhdsa` (+ `sha3` for prehash) |
| Ed25519 (RFC 8032) | `Ed25519Suite`, `Ed25519PreHashSuite` | `curve25519` (+ `sha2` for prehash) |
| ECDSA-P256 (FIPS 186-5) | `EcdsaP256Suite` | `p256`, `sha2` |
| Classical+PQ hybrid composite | `MlDsa{44,65}{Ed25519,EcdsaP256}Suite` | `mldsa`, `sha3`, (`curve25519` or `p256`), `sha2` |
| PQ-only hybrid composite | `MlDsa{44,65,87}SlhDsa{128f,192f,256f}Suite` | `mldsa`, `sha3`, `slhdsa` |

See [signaturesuite.md](./signaturesuite.md) for the full catalog, per-suite tables, hybrid composite wire formats, and the `SignatureSuite` interface.

---

## Security Model

Every signature binds the message bytes to a caller-supplied `ctx`. The envelope carries `ctx` on the wire and the verifier compares it against the receiver-supplied `ctx` in constant time before any cryptographic work runs. A mismatch fails fast with `SigningError('sig-ctx-mismatch')`.

> [!IMPORTANT]
> **`SignStream` and `VerifyStream` are single-use.** After `finalize()` returns, the stream is finalized and further `update()` calls throw `SigningError('sig-stream-finalized')`. After `dispose()` returns, any operation throws `SigningError('sig-stream-disposed')`. Construct a new stream for each message.
>
> **`SignStream` and `VerifyStream` require a `StreamableSignatureSuite`.** Pure-mode suites (`Ed25519Suite`, `MlDsa{44,65,87}Suite`, `SlhDsa{128f,192f,256f}Suite`) are rejected at the type level. Streaming requires a prehash so the suite can drive the digest incrementally; pure-mode suites bind the full message bytes and cannot stream. Use the matching `*PreHashSuite` variant for chunked input.
>
> **`ctx` is required on every call.** Pass an empty `Uint8Array` if you have no context, never `undefined` and never a missing positional argument. The wire ctx slot is `Uint8Array(0)` in that case. Some suites reject non-empty `ctx` outright (`Ed25519Suite` and `EcdsaP256Suite`); see [signaturesuite.md](./signaturesuite.md) for the per-suite contract.
>
> **Hybrid suites run both sub-verifies on every call.** Classical+PQ hybrids (`0x20`-`0x23`) and PQ-only hybrids (`0x30`-`0x32`) AND-reduce the two boolean outcomes after both verifies have completed. A timing observer cannot distinguish which half failed. See [signaturesuite.md](./signaturesuite.md#classicalpq-hybrid-composite-encoding) for the rationale.

### WASM Side-Channel Posture

All cryptographic computation runs in WASM outside the JavaScript JIT. ML-DSA's NTT and rejection sampling, SLH-DSA's hash-tree authentication, Ed25519's scalar multiplication, and ECDSA-P256's scalar multiplication are written for constant-time execution on attacker-supplied bytes. WASM lacks hardware-level constant-time guarantees, so this provides stronger posture than pure JavaScript but weaker than native constant-time code. If timing side channels are your primary threat model, a native cryptographic library with verified constant-time guarantees is more appropriate.

---

## Wire Format

### Attached envelope

`Sign.sign` and `SignStream` emit the same byte sequence. The layout is one suite byte, one ctx length byte, the user ctx bytes, a four-byte payload-length header, the payload, and finally the signature.

```
byte  0                                 : suite_byte    (u8, suite.formatEnum)
byte  1                                 : ctx_len       (u8, 0..255)
bytes 2 .. 2+ctx_len                    : ctx           (raw user_ctx, no domain prefix)
bytes 2+ctx_len .. 2+ctx_len+4          : payload_len   (u32 big-endian, 0..2^32 - 1)
bytes 2+ctx_len+4 .. payload_end        : payload       (exactly payload_len bytes)
bytes payload_end .. N                  : sig           (variable, <= suite.sigMaxSize bytes)
```

Total size is `2 + ctx_len + 4 + payload_len + sig.length`. The explicit `payload_len` field lets the sig slot float, which is required for variable-length signature schemes (composite ECDSA, whose `Ecdsa-Sig-Value` DER encoding per RFC 3279 §2.2.3 varies with leading-zero stripping). For fixed-length suites the trailing sig fills exactly `suite.sigMaxSize` bytes; the suite's verify path enforces the exact length. The 4-byte overhead is rounding error on PQ signature sizes (under 0.2% on a ~2500-byte ML-DSA-44 sig) and irrelevant on multi-megabyte signed blobs.

> [!NOTE]
> The wire carries the raw `user_ctx`, not the `effective_ctx` the suite builds internally. The receiver passes its own `ctx` to `Sign.verify` or `VerifyStream`, the envelope layer compares it against the wire ctx in constant time, and the suite reconstructs `effective_ctx` for the underlying primitive. The wire bytes do not encode the suite's `ctxDomain`.

### Parser flow (attached verify)

1. Validate `blob.length >= 6`. The minimum legal blob carries the fixed 1+1+4-byte header even with empty ctx and empty payload. Fail with `sig-blob-too-short`.
2. Read `suite_byte`. Compare against `suite.formatEnum`. Fail with `sig-suite-mismatch`.
3. Read `ctx_len`.
4. Validate `blob.length >= 2 + ctx_len + 4` so the `payload_len` u32 fits. Fail with `sig-blob-too-short`.
5. Read `payload_len` as a u32 big-endian at offset `2 + ctx_len`.
6. Validate `2 + ctx_len + 4 + payload_len <= blob.length`. Fail with `sig-blob-too-short`.
7. Validate that the trailing sig length fits the suite's catalog upper bound, `blob.length - (2 + ctx_len + 4 + payload_len) <= suite.sigMaxSize`. Fail with `sig-blob-too-short`.
8. Slice `ctx`, `payload`, and `sig` from the known offsets.
9. Compare caller `ctx` against wire `ctx` in constant time. Fail with `sig-ctx-mismatch`.
10. Call `suite.verify(pk, payload, sig, wire_ctx)`. A `false` return becomes `verify-failed`. For fixed-length suites this is where the exact sig-length check happens; for variable-length suites the suite's verify path handles parsing the sig.
11. Return `payload` on success.

All wire-shape overflows fold into `sig-blob-too-short` so the discriminator count stays stable across the wire upgrade. The error message names the specific overflow (short header, ctx past blob end, payload past blob end, trailing sig over `sigMaxSize`); callers that want a sharper diagnostic read the thrown `SigningError`'s `.message`. `sig-suite-unknown` is reserved for a future routing API that resolves the suite from the wire byte; callers always pass the suite explicitly today, so the discriminator never fires here.

### Detached signature

`Sign.signDetached` returns raw signature bytes (length at most `suite.sigMaxSize`; for fixed-length suites the length is exactly the catalog value). No header, no metadata. The caller manages the `(suite, pk, msg, sig, ctx)` tuple out of band. Use detached signatures when the message is transported separately, or when the wire format must match an external standard (CMS, COSE, JWS) that frames the signature itself.

---

## API Reference

### Sign

`Sign` is a static class, never instantiated. It handles one-shot signing and verification in both attached-envelope and detached forms, plus a peek helper for envelope inspection without verification. A `Sign.sign` blob is structurally identical to a single-`update()` `SignStream` output for the same suite, key, and inputs.

```typescript
import { init, Sign, MlDsa65Suite } from 'leviathan-crypto'
import { mldsaWasm } from 'leviathan-crypto/mldsa/embedded'
import { sha3Wasm }  from 'leviathan-crypto/sha3/embedded'

await init({ mldsa: mldsaWasm, sha3: sha3Wasm })

const { pk, sk } = MlDsa65Suite.keygen()
const msg = new TextEncoder().encode('hello world')
const ctx = new TextEncoder().encode('myapp/v1')

const blob    = Sign.sign(MlDsa65Suite, sk, msg, ctx)
const payload = Sign.verify(MlDsa65Suite, pk, blob, ctx)  // recovers msg bytes
```

| Method | Returns | Description |
|---|---|---|
| `Sign.sign(suite, sk, msg, ctx)` | `Uint8Array` | One-shot sign. Returns the attached envelope. |
| `Sign.verify(suite, pk, blob, ctx)` | `Uint8Array` | One-shot verify. Returns the recovered payload. Throws `SigningError` on suite mismatch, ctx mismatch, malformed envelope, or invalid signature. |
| `Sign.signDetached(suite, sk, msg, ctx)` | `Uint8Array` | Detached sign. Returns raw signature bytes (no envelope). |
| `Sign.verifyDetached(suite, pk, msg, sig, ctx)` | `boolean` | Detached verify. Returns `true` on valid signature, `false` otherwise. Throws `SigningError` only on contract violations (wrong-length key, ctx too long). |
| `Sign.peek(blob, suite)` | `PeekMeta` | Inspect envelope structure without verifying. Returns `{ suiteByte, ctx, payloadOffset, payloadLength, sigOffset }`. Use for routing or logging; always follow up with `Sign.verify` before trusting the payload. |

**`ctx`.** Required `Uint8Array` carrying authenticated context. Pass `new Uint8Array(0)` if you have no context. Authenticated but not encrypted; bound into the signature via the suite's `effective_ctx` construction. Pass the same value on sign and verify, or verify rejects with `sig-ctx-mismatch`.

#### Detached signature

```typescript
const sig = Sign.signDetached(MlDsa65Suite, sk, msg, ctx)
const ok  = Sign.verifyDetached(MlDsa65Suite, pk, msg, sig, ctx)
// ok === true; for fixed-length suites sig is exactly MlDsa65Suite.sigMaxSize bytes
```

#### Peek for routing

```typescript
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

---

### SignStream

> [!NOTE]
> All stream classes require a `StreamableSignatureSuite`, which means a prehash variant. Pure-mode suites are a compile-time error.

```typescript
import { init, SignStream, MlDsa65PreHashSuite } from 'leviathan-crypto'
import { mldsaWasm } from 'leviathan-crypto/mldsa/embedded'
import { sha3Wasm }  from 'leviathan-crypto/sha3/embedded'

await init({ mldsa: mldsaWasm, sha3: sha3Wasm })

const { pk, sk } = MlDsa65PreHashSuite.keygen()
const ctx = new TextEncoder().encode('myapp/v1')

const signer = new SignStream(MlDsa65PreHashSuite, sk, ctx)
signer.update(chunk1)
signer.update(chunk2)
const sig = signer.finalize()
const payloadLen = chunk1.length + chunk2.length
const preamble   = signer.buildPreamble(payloadLen)
// wire output is preamble || chunk1 || chunk2 || sig
signer.dispose()
```

**Constructor:** `new SignStream(suite, sk, ctx)`

| Parameter | Type | Description |
|---|---|---|
| `suite` | `StreamableSignatureSuite` | Any prehash-mode or hybrid suite. Pure-mode suites are rejected at the type level. |
| `sk` | `Uint8Array` | Secret key. Must be `suite.skSize` bytes. |
| `ctx` | `Uint8Array` | Authenticated context. Required; pass `new Uint8Array(0)` if you have no context. Copied into a lib-owned buffer. |

| Method | Returns | Description |
|---|---|---|
| `update(chunk)` | `void` | Drive the running prehash with one chunk. Accepts arbitrarily-sized `Uint8Array`. |
| `finalize()` | `Uint8Array` | Finalize the prehash, sign the digest, and return the signature bytes. Wipes the running prehash. |
| `buildPreamble(payloadLength)` | `Uint8Array` | Build the envelope preamble `(suite_byte, ctx_len, ctx, payload_len)` for the caller-known payload length. Safe to call any time before `dispose()`. |
| `dispose()` | `void` | Wipe the ctx copy. Idempotent. Call once the envelope blob is assembled. |

The canonical assembly pattern is `finalize()` first, then `buildPreamble()` with the payload length, then concatenate `preamble || payload || sig`. The ctx copy survives `finalize()` deliberately so `buildPreamble()` can read it; `dispose()` wipes the copy.

---

### VerifyStream

```typescript
import { init, VerifyStream, MlDsa65PreHashSuite } from 'leviathan-crypto'
import { mldsaWasm } from 'leviathan-crypto/mldsa/embedded'
import { sha3Wasm }  from 'leviathan-crypto/sha3/embedded'

await init({ mldsa: mldsaWasm, sha3: sha3Wasm })

// pk and ctx must match the SignStream side
const verifier = new VerifyStream(MlDsa65PreHashSuite, pk, ctx)
verifier.update(preamble)
verifier.update(chunk1)
verifier.update(chunk2)
verifier.update(sig)
const payload = verifier.finalize()  // throws SigningError on bad sig
verifier.dispose()
```

**Constructor:** `new VerifyStream(suite, pk, ctx)`

Throws if the wire `suite_byte` does not match `suite.formatEnum`, or if the wire `ctx` does not match the caller-supplied `ctx`.

| Parameter | Type | Description |
|---|---|---|
| `suite` | `StreamableSignatureSuite` | Must match the suite that produced the wire bytes. |
| `pk` | `Uint8Array` | Public key. Must be `suite.pkSize` bytes. |
| `ctx` | `Uint8Array` | Expected context. Compared in constant time against the wire ctx. |

| Method | Returns | Description |
|---|---|---|
| `update(chunk)` | `void` | Feed wire bytes in. Accepts arbitrarily-sized chunks; the stream parses the 6-byte header (`suite_byte`, `ctx_len`, `ctx`, `payload_len`) byte-by-byte, then consumes exactly `payload_len` bytes of payload, then buffers the trailing bytes as the sig. |
| `finalize()` | `Uint8Array` | Verify the signature against the buffered payload and return the payload bytes. Throws `SigningError` on `sig-suite-mismatch`, `sig-ctx-mismatch`, `sig-blob-too-short`, or `verify-failed`. Wipes the internal payload, sig, and header buffers on both success and failure. |
| `dispose()` | `void` | Wipe internal buffers. Idempotent. |

A receiver that does not yet know which suite produced the wire bytes can call `Sign.peek` against the leading bytes before constructing `VerifyStream`.

---

### Memory hygiene

The signing layer holds two copies of secret-adjacent state for streams. The library wipes its copies on well-defined boundaries; caller-owned buffers (`sk`, `pk`, `msg`, `sig`, the user `ctx`) are never touched.

**`SignStream`.** `new SignStream(suite, sk, ctx)` copies `ctx` into a lib-owned `Uint8Array`. `sk` is held by reference and never wiped. The running prehash is disposed in both `finalize()` and `dispose()`. The ctx copy survives `finalize()` so `buildPreamble()` can still read it; call `dispose()` once the blob is assembled.

**`VerifyStream`.** `update(chunk)` copies every payload byte into an internally-owned chunk so a caller-side mutation cannot retroactively change the buffered payload. `pk` and the expected `ctx` are held by reference and never wiped. `finalize()` wipes `payloadChunks`, `sigBuf`, and `headerBuf` on every code path; the returned payload is a fresh `concat(...)` allocation, so wiping the internal chunks does not corrupt the result. `dispose()` performs the same wipe and is idempotent.

See [signaturesuite.md](./signaturesuite.md#memory-hygiene) for the suite-layer wipe discipline (`effective_ctx`, one-shot prehash digests, ECDSA-P256 hedging entropy).

---

### SigningError

`Sign.sign`, `Sign.verify`, `Sign.signDetached`, `Sign.verifyDetached`, `Sign.peek`, `SignStream`, and `VerifyStream` all throw `SigningError(discriminator, message?)` on contract violations and verification failures. The discriminator is the stable, machine-readable identifier; the message carries human-readable context.

```typescript
import { SigningError } from 'leviathan-crypto'

try {
  const payload = Sign.verify(MlDsa65Suite, pk, tampered, ctx)
} catch (e) {
  if (e instanceof SigningError) {
    // e.discriminator: stable identifier (see table below)
    // e.message: human-readable context
  }
}
```

| Discriminator | Layer | Trigger |
|---|---|---|
| `sig-key-size` | suite | Wrong-length `sk` or `pk` for the suite. |
| `sig-ctx-too-long` | suite | `user_ctx` exceeds USER_CTX_MAX (255 bytes per FIPS 204 §3.6.1), or the combined `effective_ctx` exceeds the same cap. |
| `sig-ctx-unsupported` | suite | Non-empty `user_ctx` passed to a suite with no native context parameter (`Ed25519Suite`, `EcdsaP256Suite`). Context-bound signing must use a prehash or hybrid suite. |
| `sig-malformed-input` | suite | Primitive validation failure, for example a wrong-length digest in `signPrehashed` or `verifyPrehashed`. |
| `sig-blob-too-short` | envelope | Wire-shape rejection. Fires on a blob shorter than the 6-byte envelope header, on `ctx_len` pushing past the blob end, on `payload_len` pushing the payload past the blob end, or on a trailing sig larger than `suite.sigMaxSize`. The thrown `.message` names the specific overflow. |
| `sig-suite-unknown` | envelope | Wire `suite_byte` is not in the catalog. Reserved; callers pass the suite explicitly today, so this discriminator does not fire. |
| `sig-suite-mismatch` | envelope, stream | Wire `suite_byte` does not equal the caller's `suite.formatEnum`. |
| `sig-ctx-overflow` | envelope | Reserved for future routing APIs; the v3 envelope folds the ctx-past-blob case into `sig-blob-too-short`. |
| `sig-ctx-mismatch` | envelope, stream | Caller `ctx` does not equal wire `ctx`. Constant-time compared. |
| `verify-failed` | envelope | `suite.verify` returned false during envelope verify. |
| `sig-stream-finalized` | stream | `update()` called after `finalize()`. |
| `sig-stream-disposed` | stream | Any operation on a disposed stream. |

`VerifyStream.finalize` also throws `verify-failed` and `sig-blob-too-short` (the latter when finalize fires before enough bytes have arrived for a full signature).

Never attempt to recover the payload after a `SigningError`. `VerifyStream.finalize` wipes its internal buffers before throwing.

---

## Cross-References

| Document | Description |
| -------- | ----------- |
| [index](./README.md) | Project Documentation index |
| [lexicon](./lexicon.md) | Glossary of cryptographic terms |
| [architecture](./architecture.md) | Repository structure, build and CI, WASM modules, public API, test suite, and security posture |
| [signaturesuite](./signaturesuite.md) | `SignatureSuite` interface, full suite catalog, hybrid composite wire formats, ctx-domain construction, format-byte allocation |
| [mldsa](./mldsa.md) | ML-DSA (FIPS 204) raw primitives |
| [slhdsa](./slhdsa.md) | SLH-DSA (FIPS 205) raw primitives |
| [ed25519](./ed25519.md) | Ed25519 (RFC 8032) raw primitives |
| [ecdsa-p256](./ecdsa-p256.md) | ECDSA-P256 (FIPS 186-5) raw primitives |
| [aead](./aead.md) | `Seal`, `SealStream`, `OpenStream`, `SealStreamPool` (authenticated encryption counterpart) |
| [exports](./exports.md) | complete export reference |
| [init](./init.md) | WASM loading and `WasmSource` |
