<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### ECDSA-P256: Elliptic Curve Digital Signatures over NIST P-256

Classical digital signatures via ECDSA (FIPS 186-5 §6, ECDSA
Signature Algorithm) over the NIST P-256 curve (SP 800-186
§3.2.1.3, P-256). Hedged-or-deterministic K derivation per
RFC 6979 §3.2 and `draft-irtf-cfrg-det-sigs-with-noise-05` §4,
strict verification with low-S enforcement per RFC 6979 §3.5.

> ### Table of Contents
> - [Overview](#overview)
> - [Init](#init)
> - [ECDSA-P256 API](#ecdsa-p256-api)
> - [Point Decompression](#point-decompression)
> - [ECPrivateKey DER Codec](#ecprivatekey-der-codec)
> - [DER Utility](#der-utility)
> - [Hedged vs Deterministic](#hedged-vs-deterministic)
> - [Validation Behavior](#validation-behavior)
> - [Key & Signature Format](#key--signature-format)
> - [Wipe Discipline](#wipe-discipline)
> - [Fault-Injection Defense](#fault-injection-defense)
> - [Low-S Enforcement](#low-s-enforcement)
> - [Error Reference](#error-reference)
> - [SignatureSuites](#signaturesuites)
> - [Cross-references](#cross-references)

---

## Overview

ECDSA over P-256 is the classical ECDSA instance defined by
FIPS 186-5 §6, ECDSA Signature Algorithm, parameterised by the
NIST P-256 curve from SP 800-186 §3.2.1.3, P-256, paired with
SHA-256 as the message hash. Signatures are 64 bytes raw r || s,
public keys are 33 bytes compressed per SEC 1 §2.3.3 (compressed
elliptic-curve point), and the secret key is the 32-byte private
scalar d in `[1, n-1]` per FIPS 186-5 §A.2.1, Private Key
Generation by Testing Candidates. K-derivation has two modes:
deterministic per RFC 6979 §3.2 and hedged-deterministic per
`draft-irtf-cfrg-det-sigs-with-noise-05` §4, Hedged-Deterministic
Nonce Generation.

leviathan-crypto's posture: hedged-by-default at the suite layer,
low-S enforced on both signer and verifier, raw r || s as the
canonical wire form. DER encoding (RFC 3279 §2.2.3, ECDSA
Signature Algorithm) is exposed as a side utility for X.509,
JWS, and TLS interop; the WASM ABI and `EcdsaP256Suite` wire
format both use raw r || s. Verification rejects high-S
malleated signatures, off-curve or identity-element public keys,
out-of-range r or s, and signature equations that fail. The
class returns `false` for every cryptographic rejection; only
caller-contract violations (wrong-length inputs) throw.

ECDSA-P256 differs from Ed25519 on three operational axes. There
is no native context parameter (FIPS 186-5 §6.4, ECDSA Signature
Generation, parametrises sign on `(d, hash, k)` only), so the
suite rejects non-empty `user_ctx` rather than binding it.
ECDSA requires the caller to compute a message hash explicitly,
either by handing a digest to the `EcdsaP256` class or by
letting `EcdsaP256Suite` drive SHA-256 on the message bytes.
The signing nonce is hedged by default rather than fully
deterministic, because RFC 6979's pure-deterministic
construction exposes the long-term scalar `d` to fault-injection
attacks that bias the K derivation; hedging mixes per-call
entropy so each signature has independent nonce state. See
[Hedged vs Deterministic](#hedged-vs-deterministic) for the
trade-off.

The test corpus pins RFC 6979 §A.2.5 (P-256 + SHA-256) as the
deterministic-K gate, the NIST ACVP ECDSA-FIPS186-5 keyGen /
sigGen / sigVer records filtered to P-256 + SHA-256, and the
C2SP Wycheproof `ecdsa_secp256r1_sha256_p1363` corpus for the
strict-gate plus malleability surface. The Rust verifier
(`scripts/verify-vectors/`) re-runs every record against
RustCrypto's `p256` + `ecdsa` crates; see
[vector_audit.md](./vector_audit.md) for the verifier's
coverage and what the audit does not claim.

---

## Init

```typescript
import { init }     from 'leviathan-crypto'
import { p256Wasm } from 'leviathan-crypto/ecdsa/embedded'

await init({ p256: p256Wasm })
```

The `leviathan-crypto/ecdsa/embedded` subpath exports the WASM
blob under two names that resolve to the same string: `p256Wasm`
(canonical, matches the underlying WASM module name) and
`ecdsaP256Wasm` (alias that reads more naturally in the ecdsa
subpath context). Pick whichever matches the surrounding code;
tree-shaking is unaffected.

`p256.wasm` is the twelfth WASM binary in the library and hosts
the field arithmetic over GF(p256), the short-Weierstrass
projective point operations with Renes-Costello-Batina 2016
complete addition formulas, scalar arithmetic mod n, fixed-window
constant-time scalar multiplication, an embedded SHA-256 and
HMAC-SHA-256 driving the RFC 6979 K-derivation, and the ECDSA
high-level sign / verify / keygen entry points. The module ships
scalar (no WebAssembly SIMD); `init({ p256: ... })` works on
every WASM-capable runtime regardless of SIMD support. See
[asm_p256.md](./asm_p256.md) for the low-level module reference.

For tree-shakeable imports the `leviathan-crypto/ecdsa` subpath
exports its own init function:

```typescript
import { ecdsaP256Init } from 'leviathan-crypto/ecdsa'
import { p256Wasm }      from 'leviathan-crypto/ecdsa/embedded'

await ecdsaP256Init(p256Wasm)
```

`EcdsaP256Suite` additionally requires the `sha2` module because
the TS-side `sha256OneShot` (message-taking sign / verify paths)
and the `sha256Buffered` shim (`SignStream` running prehash)
both drive `sha2.wasm`. The substrate's embedded SHA-256 inside
`p256.wasm` is internal and used only for the RFC 6979 K
derivation; it is not exposed at the WASM ABI. Suite consumers
should initialise both modules:

```typescript
import { init }     from 'leviathan-crypto'
import { p256Wasm } from 'leviathan-crypto/ecdsa/embedded'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await init({ p256: p256Wasm, sha2: sha2Wasm })
```

---

## ECDSA-P256 API

Construction is parameter-less. Every public method runs against
the singleton `p256` instance, stages inputs at fixed offsets
above the WASM mutable region, calls the underlying export,
copies outputs to fresh `Uint8Array`s, then wipes the staged
buffers.

### Constructor

```typescript
new EcdsaP256()
```

Throws if `init({ p256: ... })` (or the subpath init) has not
been called. Cheap, runs an initialisation check and returns.

### `keygen()`

Generate a new key pair using a fresh 32-byte seed from
`crypto.getRandomValues`. Equivalent to calling `keygenDerand`
with a random seed; the local seed buffer is wiped on return.

```typescript
const ec = new EcdsaP256()
const { publicKey, secretKey } = ec.keygen()
// publicKey: 33-byte compressed pk per SEC 1 §2.3.3 (0x02 / 0x03 || x)
// secretKey: 32-byte scalar d per FIPS 186-5 §A.2.1
ec.dispose()
```

### `keygenUncompressed(seed?)`

Variant of `keygen` / `keygenDerand` that returns the public key
in the 65-byte SEC 1 §2.3.4 uncompressed encoding
`0x04 || X || Y` rather than the 33-byte compressed form. The
secret key half is the same 32-byte raw scalar `d`. Pass a seed
for deterministic derivation (equivalent to `keygenDerand`);
omit it for random-seed keygen (equivalent to `keygen`).

```typescript
const ec = new EcdsaP256()
const { publicKey, secretKey } = ec.keygenUncompressed()
// publicKey: 65-byte uncompressed pk per SEC 1 §2.3.4 (0x04 || X || Y)
// secretKey: 32-byte scalar d per FIPS 186-5 §A.2.1
ec.dispose()
```

The standalone `EcdsaP256Suite` continues to use the compressed
form returned by `keygen` / `keygenDerand`. `keygenUncompressed`
exists for callers whose wire format requires the uncompressed
encoding, notably the composite ML-DSA + ECDSA-P256 hybrid
suites whose `SerializePublicKey` routine (composite-sigs §4)
mandates `0x04 || X || Y`.

Internally calls the existing keygen path then runs
[`pointDecompress`](#point-decompression) to recover y from the
compressed result. The compressed intermediate is wiped before
return.

### `keygenDerand(seed)`

Deterministic ECDSA-P256 key generation from a 32-byte seed.
`d = seed mod n` per FIPS 186-5 §A.4.2, Testing Candidates
(single candidate), and `pk = [d]G` compressed per SEC 1 §2.3.3.
Use this when you must derive a key from a known seed (testing,
ACVP records, key escrow, deterministic deployments).

Throws `RangeError` if `seed.length !== 32`. Throws
`SigningError('sig-malformed-input')` in the vanishingly rare
`seed mod n == 0` case (probability `2^-256`); supply a
different seed.

```typescript
const seed = new Uint8Array(32)
crypto.getRandomValues(seed)

const ec = new EcdsaP256()
const { publicKey, secretKey } = ec.keygenDerand(seed)
ec.dispose()
seed.fill(0)
```

`secretKey` is a fresh copy of `seed`; `sk === seed` for this
derivation, the caller may use either as the private value.
Treat the seed with the same care as the secret key.

### `sign(sk, pk, msgHash, rnd)`

Hedged-or-deterministic ECDSA-P256 sign per FIPS 186-5 §6.4,
ECDSA Signature Generation, with RFC 6979 §3.5 low-S
normalisation. Returns a 64-byte signature `r || s`.

| Parameter | Type           | Description |
|-----------|----------------|-------------|
| `sk`      | `Uint8Array`   | 32-byte secret scalar d                                                       |
| `pk`      | `Uint8Array`   | 33-byte compressed or 65-byte uncompressed pk; cross-checked by WASM          |
| `msgHash` | `Uint8Array`   | 32-byte SHA-256(M) digest (caller-computed)                                   |
| `rnd`     | `Uint8Array`   | 32-byte per-call entropy Z (all-zero selects deterministic, non-zero hedges)  |

```typescript
import { SHA256, randomBytes } from 'leviathan-crypto'

const digest = new SHA256().hash(message)             // 32 bytes
const rnd    = randomBytes(32)                        // hedged-by-default
const sig    = ec.sign(secretKey, publicKey, digest, rnd)
const ok     = ec.verify(publicKey, digest, sig)      // true
```

The caller passes pk alongside sk; the WASM re-derives pk from
sk internally and compares it against the caller-supplied value.
A mismatch traps via `unreachable` and the TypeScript wrapper
rethrows as `SigningError('sig-malformed-input')`. See
[Fault-Injection Defense](#fault-injection-defense) for the
rationale.

ECDSA-P256 has no native context parameter (FIPS 186-5 §6.4
parametrises sign only on `(d, hash, k)`). Applications that
need context-bound signing should use a classical+PQ hybrid
suite at format byte `0x22` or `0x23` (reserved), where the PQ
half carries the ctx story.

> [!IMPORTANT]
> `EcdsaP256.sign` consumes a 32-byte digest, not a raw message.
> Compute SHA-256 at the call site (or use `EcdsaP256Suite`,
> which drives SHA-256 transparently). FIPS 186-5 §6.4 always
> hashes M before the sign equation; passing raw message bytes
> as `msgHash` produces a meaningless signature.

### `_signInternalPk(sk, msgHash, rnd)`

Suite-only entry point. Internal helper that derives pk inside
the same WASM call and skips the fault-injection cross-check,
saving one fixed-base scalar multiplication per call. Intended
for `EcdsaP256Suite` and other suite-layer callers who hold
only `sk`; the cross-check is degenerate at those call sites
because the caller-supplied pk and the WASM-derived pk both
come from the same call on the same potentially-faulted module.

Direct-class callers who hold a stored, known-good pk should
keep using `sign(sk, pk, msgHash, rnd)` to retain the
fault-injection defence. `_signInternalPk` is underscore-prefixed
and intentionally undocumented at the public API surface.

### `verify(pk, msgHash, sig)`

Strict ECDSA-P256 verify per FIPS 186-5 §6.4.4, ECDSA Signature
Verification, with low-S enforcement (RFC 6979 §3.5). Returns
`true` on success, `false` on every signature failure mode.
Throws only on caller-side contract violations (wrong-length
inputs).

```typescript
const ok = ec.verify(publicKey, digest, sig)   // boolean
```

The cryptographic checks live inside the WASM and run in this
order: pk decompresses canonically and is not the identity
element, `r` and `s` both lie in `[1, n-1]`, `s <= n/2` (low-S
strict gate), and the signature equation `r ≡ x(u1*G + u2*Q)
mod n` holds. The first three guard against malformed inputs
and malleability; the last is the FIPS 186-5 §6.4.4
verification equation. A failure in any step returns `false`.

| Parameter | Type           | Description |
|-----------|----------------|-------------|
| `pk`      | `Uint8Array`   | 33-byte compressed or 65-byte uncompressed pk     |
| `msgHash` | `Uint8Array`   | 32-byte SHA-256(M) digest                         |
| `sig`     | `Uint8Array`   | 64-byte raw r || s (use the DER utility to convert) |

### `dispose()`

Wipe all p256 WASM scratch memory and the TS-side I/O staging
region. Idempotent. Safe to call multiple times. Every public
method already wipes both regions on its own success and throw
paths; `dispose()` is defence-in-depth at instance teardown.

---

## Point Decompression

A free function on the `leviathan-crypto/ecdsa` subpath converts
the 33-byte SEC 1 §2.3.3 compressed encoding of a P-256 public
key into the 65-byte SEC 1 §2.3.4 uncompressed encoding. The
substrate's `pointDecompress` recovers y by solving
`y² = x³ - 3x + b mod p` (SP 800-186 §3.2.1.3, P-256 has a = -3)
via the modular square root shortcut for primes p ≡ 3 (mod 4),
then selects the y root whose parity matches the compressed
prefix byte (0x02 for even-y, 0x03 for odd-y).

### `pointDecompress(pk33)`

```typescript
import { pointDecompress } from 'leviathan-crypto/ecdsa'

const compressed = ...   // 33-byte SEC 1 §2.3.3 encoding
const uncompressed = pointDecompress(compressed)
// uncompressed: Uint8Array(65), starts with 0x04
```

Returns a fresh 65-byte `Uint8Array` of the form
`0x04 || X || Y` where X and Y are the affine coordinates as
big-endian 32-byte integers. Throws on any rejection:

| Condition                                          | Throw                                 |
| -------------------------------------------------- | ------------------------------------- |
| `pk33` is not a `Uint8Array`                       | `TypeError`                           |
| `pk33.length !== 33`                               | `RangeError`                          |
| Prefix byte not in `{0x02, 0x03}`                  | `SigningError('sig-malformed-input')` |
| x coordinate has no on-curve y (non-residue y²)    | `SigningError('sig-malformed-input')` |

`pointDecompress` is what powers
[`EcdsaP256.keygenUncompressed`](#keygenuncompressed); it is also
exported as a free function for callers that hold a 33-byte
compressed pk and want the uncompressed form directly (e.g. the
composite ML-DSA + ECDSA-P256 hybrid suites at format byte
`0x22` / `0x23`, whose wire format follows composite-sigs §4 and
requires the SEC 1 §2.3.4 encoding).

Requires `init({ p256: ... })`. Concurrency-safe alongside
non-stateful uses of `EcdsaP256`; the underlying p256 module is
shared.

> [!IMPORTANT]
> `pointDecompress` consumes only the 33-byte compressed form.
> Passing a 65-byte already-uncompressed pk produces a
> `RangeError`; the leading byte of a 65-byte uncompressed pk is
> `0x04`, which is not valid as a compressed-form prefix and
> would not round-trip through this routine anyway.

---

## ECPrivateKey DER Codec

A pair of free functions on the `leviathan-crypto/ecdsa`
subpath encode and decode the DER `ECPrivateKey` structure per
RFC 5915 §3, Elliptic Curve Private Key Structure:

```
ECPrivateKey ::= SEQUENCE {
    version        INTEGER (1),
    privateKey     OCTET STRING,
    parameters [0] EXPLICIT ECParameters OPTIONAL,
    publicKey  [1] EXPLICIT BIT STRING OPTIONAL
}
```

The codec is hand-rolled; leviathan-crypto is zero-dependency, so
no external ASN.1 parser is imported. The strict-DER rules of
X.690 §10 (Restrictions on the BER) govern the decoder's
rejection surface.

### `encodeEcPrivateKey(scalar)`

```typescript
import { encodeEcPrivateKey } from 'leviathan-crypto/ecdsa'

const scalar = ...   // 32-byte raw P-256 secret scalar d
const der = encodeEcPrivateKey(scalar)
// der: Uint8Array(51), DER ECPrivateKey for P-256
```

Emits exactly 51 bytes with the following structure:

```
30 31                            SEQUENCE, 49 content bytes
02 01 01                         INTEGER, version = 1
04 20 <32 bytes scalar>          OCTET STRING, privateKey
A0 0A                            [0] EXPLICIT, 10 content bytes
06 08 2A 86 48 CE 3D 03 01 07    OBJECT IDENTIFIER, secp256r1
```

The named-curve OID `1.2.840.10045.3.1.7` (SP 800-186 §3.2.1.3)
is always included; the `publicKey [1]` field is always omitted.
Byte-stable: the same scalar input produces byte-identical output.

Throws `TypeError` on non-`Uint8Array` input; `RangeError` on
wrong-length input.

### `decodeEcPrivateKey(der)`

```typescript
import { decodeEcPrivateKey } from 'leviathan-crypto/ecdsa'

const scalar = decodeEcPrivateKey(der)
// scalar: Uint8Array(32), raw P-256 secret scalar d
```

Decodes any conforming RFC 5915 §3 `ECPrivateKey` for P-256 and
returns the 32-byte raw scalar. Strict DER per X.690 §10. Rejects
(throws `Error`):

- Wrong outer tag (must be `0x30` SEQUENCE)
- Long-form length encoding on any field with content under 128
  bytes (X.690 §10.1, definite-length minimal encoding)
- Outer SEQUENCE length that does not match input size
- Wrong version tag, version length other than 1, or version
  value other than 1
- Wrong privateKey tag, or privateKey OCTET STRING length other
  than 32 (P-256 scalar size)
- `parameters [0]` containing any OID other than secp256r1
- Any content that extends past the outer SEQUENCE end
- Trailing bytes after the optional `publicKey [1]` field

Accepts (and ignores) an optional `publicKey [1]` field per
RFC 5915 §3; some encoders include the derived pk alongside the
scalar. The scalar is the only return value; callers who need
the embedded pk should re-derive from the scalar via
`EcdsaP256.keygenDerand`. Accepts the parameters-omitted minimal
form (`SEQUENCE { version, privateKey }`).

Throws `TypeError` on non-`Uint8Array` input.

Requires no module init; the codec is pure TypeScript with no
WASM dependency.

---

## DER Utility

ECDSA wire-form interop with X.509, JWS, and TLS uses the
ASN.1 DER encoding per RFC 3279 §2.2.3, ECDSA Signature
Algorithm:

```
Ecdsa-Sig-Value ::= SEQUENCE {
    r  INTEGER,
    s  INTEGER
}
```

The leviathan-crypto WASM ABI and `EcdsaP256Suite` both produce
raw 64-byte `r || s` signatures. The DER helpers convert between
raw and DER form without requiring any external ASN.1 parser.
Encoder and decoder are hand-rolled against X.690 §8.3 (INTEGER)
and §8.9 (SEQUENCE); the decoder is strict-DER and rejects
non-minimal length encodings, excess leading zero bytes, negative
INTEGERs, INTEGER content longer than 33 bytes, trailing bytes,
and wrong tags.

### `ecdsaSignatureToDer(rawSig)`

Convert a 64-byte raw `r || s` signature to DER. Output length is
variable: 8 bytes minimum (`r = s = 1`, no sign-pad) and 72 bytes
maximum (both components 32 bytes with the high bit set, each
picking up a 0x00 sign-pad).

```typescript
import { ecdsaSignatureToDer } from 'leviathan-crypto'

const rawSig = ec.sign(sk, pk, digest, rnd)   // 64 bytes
const derSig = ecdsaSignatureToDer(rawSig)    // 8..72 bytes
```

Throws `TypeError` if `rawSig` is not a `Uint8Array`. Throws
`RangeError` if `rawSig.length !== 64`.

### `ecdsaSignatureFromDer(derSig)`

Convert a DER signature back to 64-byte raw `r || s`. Rejects
any DER syntax violation via `SigningError('sig-malformed-input')`:
wrong outer / inner tag, long-form length for content under
128 bytes, non-minimal INTEGER encoding (excess leading zero
byte), negative INTEGER (high bit set on first content byte
without a sign-pad), trailing bytes, and INTEGER content longer
than 33 bytes.

```typescript
import { ecdsaSignatureFromDer } from 'leviathan-crypto'

const rawSig = ecdsaSignatureFromDer(derSig)
const ok     = ec.verify(pk, digest, rawSig)
```

Throws `TypeError` if `derSig` is not a `Uint8Array`. Semantic
value rejections (`r = 0`, `s = 0`, high-S, off-range) are NOT
raised by `ecdsaSignatureFromDer`; those are verify-time
rejections in the WASM. Only DER structural violations throw at
this entry point.

Round-trip example:

```typescript
const raw  = ec.sign(sk, pk, digest, rnd)
const der  = ecdsaSignatureToDer(raw)
const raw2 = ecdsaSignatureFromDer(der)
// raw and raw2 are byte-identical
```

---

## Hedged vs Deterministic

ECDSA's K-derivation is the most operationally dangerous part
of the signature scheme. The library exposes both modes; the
`rnd` parameter to `sign(sk, pk, msgHash, rnd)` selects between
them.

### Why hedged is the default

RFC 6979 §3.2 derives `k` deterministically from `(d, H(m))`
through an HMAC-DRBG seeded with those inputs. Leaking `k` to
an attacker lets them recover `d` via the standard ECDSA
`d = (k * s - H(m)) / r mod n` recovery. The pure-deterministic
construction is fully exposed to fault-injection attacks: an
attacker who can inject a transient hardware fault into the
sk-derived intermediates can bias `k` in ways that leak `d`
over a handful of signatures. The hedged variant from
`draft-irtf-cfrg-det-sigs-with-noise-05` §4,
Hedged-Deterministic Nonce Generation, mixes per-call entropy
into the HMAC-DRBG seed so each signature has independent
nonce-derivation state; a successful fault on one call does not
transfer to the next.

`EcdsaP256Suite.sign` generates `rnd = randomBytes(32)` per
call, threads it through `EcdsaP256._signInternalPk`, and wipes
the buffer in the `finally` block. Two calls to
`EcdsaP256Suite.sign(sk, msg, EMPTY_CTX)` over the same
`(sk, msg)` return DIFFERENT signatures (the rnd differs).
Both verify under the same pk. This is the recommended posture
for v3 signing.

### How to get deterministic behavior

Pass `rnd = new Uint8Array(32)` (all-zero) to
`EcdsaP256.sign(sk, pk, msgHash, rnd)`. The WASM detects the
all-zero buffer and routes through the verbatim RFC 6979 §3.2
construction. Two calls with the same `(sk, msgHash)` produce
byte-identical signatures.

```typescript
const rndZero = new Uint8Array(32)
const sig1    = ec.sign(sk, pk, digest, rndZero)
const sig2    = ec.sign(sk, pk, digest, rndZero)
// sig1 and sig2 are byte-identical (RFC 6979 §3.2 deterministic)
```

Deterministic ECDSA is required for some interop scenarios
(byte-exact KAT reproduction, audit trails, externally-witnessed
signing ceremonies). The suite layer does not expose this knob
because per-call entropy is the safety-by-default posture; drop
down to `EcdsaP256` directly when you need bytes-stable output.

### Trade-off

Deterministic ECDSA is RFC-mandated for interop with signers
that reproduce RFC 6979 §A.2.5 vectors byte-for-byte; the cost
is full exposure to fault-injection-on-K attacks. Hedged ECDSA
preserves the safety-by-default per-call independence at the
cost of giving up byte-stable signatures. The library defaults
to hedged everywhere a default is taken; the deterministic path
is available for callers with an explicit interop requirement.

---

## Validation Behavior

`EcdsaP256` distinguishes two failure classes: verification
failures (binary, return false) versus caller-contract
violations (throw `TypeError`, `RangeError`, or
`SigningError`). The split follows FIPS 186-5 §6.4.4
Verification.

| Condition                                                | `sign` / variants  | `verify`           |
| -------------------------------------------------------- | ------------------ | ------------------ |
| Input not a `Uint8Array`                                 | throw `TypeError`  | throw `TypeError`  |
| `seed.length !== 32`                                     | throw `RangeError` | n/a                |
| `sk.length !== 32`                                       | throw `RangeError` | n/a                |
| `pk.length` not 33 or 65                                 | throw `RangeError` | throw `RangeError` |
| `msgHash.length !== 32`                                  | throw `RangeError` | throw `RangeError` |
| `rnd.length !== 32`                                      | throw `RangeError` | n/a                |
| `sig.length !== 64`                                      | n/a                | throw `RangeError` |
| `seed mod n == 0` on `keygenDerand`                      | `SigningError`     | n/a                |
| Caller pk does not match pk derived from sk on `sign`    | `SigningError`     | n/a                |
| Off-curve / non-canonical pk encoding                    | n/a                | return `false`     |
| pk decompresses to the identity element                  | n/a                | return `false`     |
| `r` or `s` outside `[1, n-1]`                            | n/a                | return `false`     |
| `s > n/2` (high-S, strict-gate)                          | n/a                | return `false`     |
| Signature equation `r != x(u1*G + u2*Q) mod n`           | n/a                | return `false`     |

`validatePublicKey` accepts both 33-byte compressed
(SEC 1 §2.3.3) and 65-byte uncompressed (SEC 1 §2.3.4) inputs.
The wrapper normalises 65-byte inputs to the 33-byte compressed
form before staging in WASM memory (the WASM ABI consumes
compressed only). Constant-time is not required at pk import
because pk is public material.

Wrong-shape inputs are caller mistakes and throw so the bug
surfaces immediately. Cryptographic failures map to `false`
because they are indistinguishable from a wrong-key attempt
and should not raise as exceptions. The high-S rejection on
`verify` is part of the leviathan-crypto strict-gate posture
and is exercised by the Wycheproof p1363 corpus; FIPS 186-5
§6.4.4 itself permits high-S, but rejecting it closes the
signature malleability surface.

---

## Key & Signature Format

Public key pk, SEC 1 §2.3.3, compressed elliptic-curve point:

```
pk = 0x02 || x        (y is even)
pk = 0x03 || x        (y is odd)
```

33 bytes total. Byte 0 is the prefix (`0x02` for even-y,
`0x03` for odd-y), bytes 1..33 carry the x-coordinate as a
big-endian 32-byte integer modulo `p`. The 65-byte uncompressed
form (SEC 1 §2.3.4, `0x04 || x || y`) is accepted at import
and normalised to compressed; the WASM ABI only consumes the
33-byte form, and the canonical wire form across the library
is compressed.

Secret key sk, FIPS 186-5 §A.2.1, Private Key Generation by
Testing Candidates:

```
sk = d   (32 bytes, big-endian, d ∈ [1, n-1])
```

The signer treats sk as the private scalar d directly. The
`keygenDerand` helper applies `d = seed mod n`; the
vanishingly rare `seed mod n == 0` case traps and is rethrown
as a `SigningError`. Treat sk with the standard secret-key
custody discipline.

Signature sig, FIPS 186-5 §6.4, ECDSA Signature Generation:

```
sig = r || s   (64 bytes, big-endian r and s, low-S)
```

64 bytes total. Bytes 0..32 carry `r` as a big-endian 32-byte
integer in `[1, n-1]`; bytes 32..64 carry `s` as the same. The
signer always normalises `s` to low-S (`s = min(s, n - s)`) per
RFC 6979 §3.5, so the verifier never sees a high-S signature
from the library. The verifier additionally rejects any high-S
signature received from another source as part of the
strict-gate posture; see [Low-S Enforcement](#low-s-enforcement).

The curve order n is

```
n = 0xFFFFFFFF 00000000 FFFFFFFF FFFFFFFF
    BCE6FAAD A7179E84 F3B9CAC2 FC632551
```

per SP 800-186 §3.2.1.3, P-256.

DER-encoded signatures (RFC 3279 §2.2.3) are a side
representation produced by `ecdsaSignatureToDer` and consumed
by `ecdsaSignatureFromDer`. Use them for X.509, JWS, or TLS
interop; the raw form is canonical inside this library.

---

## Wipe Discipline

Every `EcdsaP256` public method ends with a two-phase wipe:

1. The WASM-side `wipeBuffers` export zeroes the mutable region
   from `MUTABLE_START` (4096) to `BUFFER_END` (7054). That
   covers the scratch field elements, scratch projective points,
   scratch scalars, the HMAC-DRBG K / V state used by the RFC
   6979 K derivation, the embedded SHA-256 streaming state and
   message schedule, and the ECDSA fault-check buffers.
2. The TypeScript wrapper zeroes the I/O staging region above
   `BUFFER_END` to the end of linear memory. The WASM does not
   own that region; the wrapper owns it and is responsible for
   the wipe. The seed slot, sk slot, pk slot, signature slot,
   msgHash slot, and per-call rnd slot all live here.

Both phases run inside a `try / finally` so the wipe fires on
the success path and on every throw path, including the
fault-injection trap. Caller-supplied buffers (sk, pk, msgHash,
rnd, sig) are NEVER mutated; the library copies them into the
staging region.

Per-call `rnd` is secret-equivalent at sign time: knowing rnd
lets an attacker recover k and then d via the standard
ECDSA-with-known-k recovery. `EcdsaP256Suite.sign` wipes its
locally-allocated rnd in `finally` after every signature.
Direct-class callers who supply their own `rnd` are responsible
for wiping it themselves.

`dispose()` re-runs both wipe phases as defence-in-depth at
instance teardown. Calling it multiple times is safe.

---

## Fault-Injection Defense

`EcdsaP256.sign` accepts the public key alongside the secret
key. The WASM ignores the caller-supplied pk during the actual
signing equation and re-derives pk from sk via `[d]G`; it then
compares the derived value byte-for-byte against the
caller-supplied buffer and aborts via `unreachable` if they
differ.

This defends against a narrow but documented attack class. The
RFC 6979 §3.2 K derivation reads sk (the scalar d) and the
message digest into an HMAC-DRBG; a fault-injection attacker who
can flip bits in either input can bias k in ways that leak d
through standard ECDSA-with-known-k recovery. Forcing the
signer to also know the encoded pk means the attacker must
know both the seed and the derived public key, which removes
any advantage from a sk-only fault.

The TypeScript wrapper catches the `WebAssembly.RuntimeError`
that an `unreachable` trap raises and rethrows it as
`SigningError('sig-malformed-input', ...)` so callers can
branch on the failure. The cost is one extra fixed-base scalar
multiplication per sign; verifies are unaffected (verify
operates on public inputs).

`EcdsaP256Suite` at the envelope layer routes through the
unexported `_signInternalPk` helper, which derives pk inside
the same WASM call and skips the cross-check. At the suite
call site the comparison would be between two outputs of the
same potentially-faulted module on the same call, so the
defence collapses to no defence; skipping it saves one
fixed-base scalar mult per sign on the hot path that every
`Sign` and `SignStream` invocation traverses. Callers who care
about the fault-injection defence should drop down to
`EcdsaP256` directly with their stored pk.

---

## Low-S Enforcement

ECDSA has a signature-malleability surface that Ed25519 does
not. Given any valid signature `(r, s)`, the pair `(r, n - s)`
is also a valid signature under the same `(pk, msgHash)`
because the verification equation only constrains `s mod n`.
An attacker who intercepts a signature can flip `s` to its
high-S counterpart and produce a second signature that verifies
under the same key; protocols that hash or compare signature
bytes (signed-message dedup, blockchain transaction ids) break
under this transformation.

RFC 6979 §3.5 mandates low-S for deterministic ECDSA: the
signer must normalise `s = min(s, n - s)` so the canonical
output never appears in its high-S form. leviathan-crypto
extends the rule to the hedged path: every signature emitted
by `EcdsaP256.sign` and `EcdsaP256._signInternalPk` is low-S
regardless of K mode. The WASM signer normalises `s` before
returning.

The verifier carries the same posture in reverse: any signature
with `s > n/2` is rejected before the signature equation
evaluates. `EcdsaP256.verify(pk, msgHash, sig)` returns `false`
on high-S input rather than accepting and computing.
Wycheproof's `ecdsa_secp256r1_sha256_p1363` corpus exercises
every malleability variant and confirms that the strict-gate
fires on every spec-defined malleation. See
[vector_audit.md](./vector_audit.md) for the verifier coverage.

> [!IMPORTANT]
> FIPS 186-5 §6.4.4 itself does NOT mandate low-S on verify.
> A signature with high-S that fails under
> `EcdsaP256.verify` might pass under a FIPS 186-5-compliant
> verifier elsewhere in the ecosystem. The strict-gate posture
> is leviathan-crypto's choice; the Rust verifier explicitly
> disables `NORMALIZE_S` and matches FIPS 186-5 verbatim so
> the test corpus reconciles ACVP records (`testPassed`)
> against the strict-gate behaviour. See
> [vector_audit.md §ECDSA-P256](./vector_audit.md) for the
> reconciliation.

---

## Error Reference

| Error                                                                                                  | Cause                                                                            |
| ------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------- |
| `Error: leviathan-crypto: call init({ p256: ... }) before using EcdsaP256`                             | Class constructor invoked before init.                                           |
| `TypeError: leviathan-crypto: ecdsa-p256 seed must be a Uint8Array`                                    | `keygenDerand` passed a non-`Uint8Array` seed.                                   |
| `RangeError: leviathan-crypto: ecdsa-p256 seed must be 32 bytes (got N)`                               | `keygenDerand` passed a wrong-length seed.                                       |
| `TypeError: leviathan-crypto: ecdsa-p256 secret key must be a Uint8Array`                              | `sign` or `_signInternalPk` passed a non-`Uint8Array` sk.                        |
| `RangeError: leviathan-crypto: ecdsa-p256 secret key must be 32 bytes (got N)`                         | `sign` or `_signInternalPk` passed a wrong-length sk.                            |
| `TypeError: leviathan-crypto: ecdsa-p256 public key must be a Uint8Array`                              | Any method passed a non-`Uint8Array` pk.                                         |
| `RangeError: leviathan-crypto: ecdsa-p256 public key must be 33 bytes ...or 65 bytes ...(got N)`       | Any method passed a wrong-length pk.                                             |
| `TypeError: leviathan-crypto: ecdsa-p256 message hash must be a Uint8Array`                            | `sign` or `verify` passed a non-`Uint8Array` digest.                             |
| `RangeError: leviathan-crypto: ecdsa-p256 message hash must be 32 bytes (got N)`                       | `sign` or `verify` passed a wrong-length digest.                                 |
| `TypeError: leviathan-crypto: ecdsa-p256 entropy must be a Uint8Array`                                 | `sign` or `_signInternalPk` passed a non-`Uint8Array` rnd.                       |
| `RangeError: leviathan-crypto: ecdsa-p256 entropy must be 32 bytes (got N)`                            | `sign` or `_signInternalPk` passed a wrong-length rnd.                           |
| `TypeError: leviathan-crypto: ecdsa-p256 signature must be a Uint8Array`                               | `verify` passed a non-`Uint8Array` sig.                                          |
| `RangeError: leviathan-crypto: ecdsa-p256 signature must be 64 bytes raw r\|\|s (got N)`               | `verify` passed a wrong-length sig.                                              |
| `SigningError('sig-malformed-input', 'leviathan-crypto: ecdsa-p256 keygen aborted, seed mod n is zero...')` | `keygenDerand` hit the `2^-256` `seed mod n == 0` case.                          |
| `SigningError('sig-malformed-input', 'leviathan-crypto: ecdsa-p256 sign aborted, pk does not match ...')` | Caller-supplied pk does not match pk derived from sk (fault-injection trap).     |
| `TypeError: leviathan-crypto: ecdsa-p256 DER signature must be a Uint8Array`                           | `ecdsaSignatureFromDer` passed a non-`Uint8Array`.                               |
| `TypeError: leviathan-crypto: ecdsa-p256 raw signature must be a Uint8Array`                           | `ecdsaSignatureToDer` passed a non-`Uint8Array`.                                 |
| `RangeError: leviathan-crypto: ecdsa-p256 raw signature must be 64 bytes r\|\|s (got N)`               | `ecdsaSignatureToDer` passed a wrong-length sig.                                 |
| `SigningError('sig-malformed-input', 'leviathan-crypto: ecdsa-p256 DER signature ...')`                | `ecdsaSignatureFromDer` hit a strict-DER syntax violation. See [DER Utility](#der-utility) for the rejection rules. |
| `TypeError: leviathan-crypto: ecdsa-p256 compressed public key must be a Uint8Array`                   | `pointDecompress` passed a non-`Uint8Array`.                                     |
| `RangeError: leviathan-crypto: ecdsa-p256 compressed public key must be 33 bytes (got N)`              | `pointDecompress` passed a wrong-length input.                                   |
| `SigningError('sig-malformed-input', 'leviathan-crypto: ecdsa-p256 compressed public key prefix must be 0x02 or 0x03 ...')` | `pointDecompress` passed a 33-byte input with a prefix byte outside `{0x02, 0x03}`. |
| `SigningError('sig-malformed-input', 'leviathan-crypto: ecdsa-p256 compressed public key x coordinate has no on-curve y ...')` | `pointDecompress` passed an x whose `y² = x³ - 3x + b` is a non-residue mod p (off-curve). |
| `TypeError: leviathan-crypto: ecdsa-p256 ECPrivateKey scalar must be a Uint8Array`                     | `encodeEcPrivateKey` passed a non-`Uint8Array`.                                  |
| `RangeError: leviathan-crypto: ecdsa-p256 ECPrivateKey scalar must be 32 bytes (got N)`                | `encodeEcPrivateKey` passed a wrong-length scalar.                               |
| `TypeError: leviathan-crypto: ecdsa-p256 ECPrivateKey DER must be a Uint8Array`                        | `decodeEcPrivateKey` passed a non-`Uint8Array`.                                  |
| `Error: leviathan-crypto: ecdsa-p256 ECPrivateKey DER ...`                                             | `decodeEcPrivateKey` hit a strict-DER violation. See [ECPrivateKey DER Codec](#ecprivatekey-der-codec) for the rejection rules. |

`verify` returns `false` on every signature failure (wrong sig,
off-curve pk, identity pk, out-of-range r or s, high-S, or the
signature equation mismatch). It throws only on the contract
violations above. High-S is NOT thrown on the verify path; it
returns `false`.

At the envelope layer `EcdsaP256Suite` adds one suite-layer
discriminator:

| Error                                                                            | Cause                                                                          |
| -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `SigningError('sig-ctx-unsupported', 'ecdsa-p256 does not support user context...')` | Non-empty `user_ctx` passed to `EcdsaP256Suite.sign` / `verify` / `signPrehashed` / `verifyPrehashed`. |

---

## SignatureSuites

One ECDSA-P256 suite ships:

- `EcdsaP256Suite` (format byte `0x02`), ECDSA over NIST P-256
  with SHA-256, hedged-by-default, low-S enforced. Satisfies
  `StreamableSignatureSuite` and plugs into `SignStream` /
  `VerifyStream`.

ECDSA has no native context parameter, so `EcdsaP256Suite`
rejects every non-empty user_ctx with
`SigningError('sig-ctx-unsupported')` on every entry point
(`sign`, `verify`, `signPrehashed`, `verifyPrehashed`). The
suite carries `ctxDomain = 'ecdsa-p256-envelope-v3'` for
`formatName` and display purposes, but it is never bound into
the signature. Applications that need context-bound
ECDSA-P256 should use a classical+PQ hybrid suite at format
byte `0x22` or `0x23` (reserved); the PQ half of those suites
carries the ctx story.

Unlike pure Ed25519, ECDSA-P256 conforms to
`StreamableSignatureSuite`. Every ECDSA signature internally
prehashes the message via SHA-256 (the spec REQUIRES it; ECDSA
cannot sign message bytes directly).
`SignStream(EcdsaP256Suite, sk, EMPTY_CTX)` is well-defined:
the message bytes flow through `sha256Buffered` (from
`src/ts/sign/hasher.ts`) into the underlying signature
operation, which sees only the 32-byte digest.

The suite's sign methods generate `rnd = randomBytes(32)` per
call and thread it through `EcdsaP256._signInternalPk`, so
suite consumers always get hedged signatures. Drop down to
`EcdsaP256` directly with `rnd = new Uint8Array(32)` for
byte-deterministic RFC 6979 §3.2 output.

See [signaturesuite.md](./signaturesuite.md#ecdsa-p256-suite) for
the full wire format, format-byte allocation, and worked
examples through `Sign`, `SignStream`, and `VerifyStream`.

---

## Cross-references

- [Architecture](./architecture.md), module layout and three-tier design.
- [init.md](./init.md), `init()` API and module-loader contract.
- [signaturesuite.md](./signaturesuite.md), `SignatureSuite` interface plus
  the `EcdsaP256Suite` const, `Sign`, `SignStream`, and `VerifyStream`.
- [asm_p256.md](./asm_p256.md), low-level WASM module reference.
- [ecdsa-p256_audit.md](./ecdsa-p256_audit.md), ECDSA-P256 audit checklist.
- [vector_audit.md](./vector_audit.md), test-vector tier classification and Rust verifier coverage.
- [ed25519.md](./ed25519.md), companion classical signature primitive.
- [exports.md](./exports.md), full export catalog.

External references:

- FIPS 186-5: Digital Signature Standard (DSS), 2023. ECDSA is §6.
- SP 800-186: Recommendations for Discrete Logarithm-Based Cryptography, 2023. P-256 is §3.2.1.3.
- SEC 1 v2.0: Elliptic Curve Cryptography. Compressed encoding is §2.3.3; uncompressed is §2.3.4.
- RFC 3279: Algorithms and Identifiers for the Internet X.509 PKI. ECDSA DER encoding is §2.2.3.
- RFC 6979: Deterministic Usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA). K derivation is §3.2; low-S guidance is §3.5; P-256 + SHA-256 test vectors are §A.2.5.
- `draft-irtf-cfrg-det-sigs-with-noise-05`: Hedged-deterministic nonce generation for ECDSA and EdDSA.
