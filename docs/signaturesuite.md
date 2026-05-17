<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### SignatureSuite

The extension point for the v3 signing layer. `Sign`, `SignStream`, and `VerifyStream` are scheme-agnostic. You provide the signing scheme by passing a `SignatureSuite` object at each call site or to the stream constructors.

---

> ### Table of Contents
> - [Implementations included](#implementations-included)
> - [Pure-mode suites](#pure-mode-suites)
> - [Prehash-mode suites](#prehash-mode-suites)
> - [PQ-only hybrid composite encoding](#pq-only-hybrid-composite-encoding)
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

Six ML-DSA suites ship. Three are pure-mode, satisfying `SignatureSuite`; three are prehash-mode, satisfying `StreamableSignatureSuite` and usable with `SignStream` / `VerifyStream`.

SLH-DSA (FIPS 205) and the leviathan PQ-only hybrids also ship: six SLH-DSA suites (three pure, three prehash) plus three hybrid composites that combine ML-DSA with SLH-DSA at each NIST security category. Two Ed25519 suites ship (pure plus Ed25519ph). One ECDSA-P256 suite ships (`EcdsaP256Suite`, FIPS 186-5 §6 over NIST P-256 with SHA-256, hedged-by-default per `draft-irtf-cfrg-det-sigs-with-noise-05`). Reserved for future work: the composite classical+PQ hybrids that match `draft-ietf-lamps-pq-composite-sigs`, and the Merkle log signed-tree-head surface that wires the same `SignatureSuite` shape into log proofs. The format-byte allocation at the bottom of this doc reserves a wire byte for every catalog entry, shipped or queued.

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

FIPS 204 §5.4.1 lists twelve approved prehash functions covering the SHA-2 and SHA-3 families. The ML-DSA prehash suites pick SHA3-256 for ML-DSA-44 and ML-DSA-65, SHA3-512 for ML-DSA-87. Two reasons drive the choice:

- The output size matches the parameter set's λ-derived collision target. ML-DSA-44 / 65 use λ ≥ 128, so a 256-bit digest meets the bound. ML-DSA-87 uses λ = 256, so a 512-bit digest is appropriate.
- Sticking to the SHA-3 family lets prehash suites work with `init({ mldsa, sha3 })` alone. If the suites used SHA-256 or SHA-512, every prehash consumer would need to add `sha2` to their `init` call. Future work may add SHA-2-prehash variants for protocols that mandate them.

The mldsa primitive supports all twelve §5.4.1 algorithms via `MlDsaBase.signHash` / `verifyHash`; see [mldsa.md](./mldsa.md#pre-hash-algorithms). The shipped prehash suites pin the choice for byte-stable wire interop. Future suites that need a different prehash get their own format byte rather than reusing one of the bytes above.

### MlDsa44PreHashSuite, MlDsa65PreHashSuite, MlDsa87PreHashSuite

Use these when the application cannot buffer the full message before signing, or when the consumer is a `SignStream` over chunked input. The wire is byte-identical to a `Sign.sign` call with the same parameter set and prehash, so a receiver can use either `Sign.verify` or `VerifyStream` interchangeably.

> [!IMPORTANT]
> Pure-mode and prehash-mode signatures are not interchangeable, even on the same key. HashML-DSA's M' uses a different domain-separator byte from pure ML-DSA (FIPS 204 §3.6.4). The wire format encodes which mode produced the signature via `formatEnum`; the receiver must match the suite the sender used.

### Ed25519 suites

Two classical Ed25519 suites cover RFC 8032 §5.1, Ed25519. `Ed25519Suite` (`0x01`) signs the message bytes directly in pure mode; `Ed25519PreHashSuite` (`0x11`) signs an SHA-512 prehash with the dom2(F=1, ctx) binding. Ed25519 is classical, not post-quantum, so plan for migration to a classical+PQ hybrid (`0x20` / `0x21`, reserved) when long-horizon assurance matters. See [SECURITY.md](../SECURITY.md) for the threat model. The full Ed25519 reference lives in [ed25519.md](./ed25519.md); the audit checklist lives in [ed25519_audit.md](./ed25519_audit.md).

| Field              | `Ed25519Suite`         | `Ed25519PreHashSuite`              |
|--------------------|------------------------|------------------------------------|
| `formatEnum`       | `0x01`                 | `0x11`                             |
| `formatName`       | `'ed25519'`            | `'ed25519-prehash'`                |
| `ctxDomain`        | `ed25519-envelope-v3`  | `ed25519-prehash-envelope-v3`      |
| `pkSize`           | 32                     | 32                                 |
| `skSize`           | 32                     | 32                                 |
| `sigSize`          | 64                     | 64                                 |
| `prehashAlgorithm` | n/a                    | `'sha-512'`                        |
| `prehashSize`      | n/a                    | 64                                 |
| `wasmModules`      | `['curve25519']`       | `['curve25519', 'sha2']`           |

#### Ed25519Suite (pure)

`Ed25519Suite` covers pure Ed25519, RFC 8032 §5.1.6, signature generation. Satisfies `SignatureSuite` only; `SignStream` and `VerifyStream` reject it at the type level because pure Ed25519 has no streaming prehash story (the spec hashes the full message bytes during signing).

Pure Ed25519 has no native context parameter. The suite carries a built-in `ctxDomain` of `'ed25519-envelope-v3'` for `formatName` and display purposes, but the suite rejects any non-empty user_ctx with `SigningError('sig-ctx-unsupported')`. Applications that need context-bound signing must use `Ed25519PreHashSuite`, where RFC 8032 §5.1.7, signature verification, defines the dom2(F=1, ctx) construction.

Pure Ed25519 is deterministic per RFC 8032 §5.1.6: the per-signature nonce `r = SHA-512(prefix || M)` is fully determined by the secret seed and the message. Two `Ed25519Suite.sign` calls over the same `(sk, msg)` return byte-identical signatures. This is a property of the spec, not a hedged-vs-deterministic policy choice; the suite cannot be configured to behave otherwise.

> [!IMPORTANT]
> `Ed25519Suite` has a per-call message ceiling of approximately 248 KB, the WASM module's static input-staging cap. Messages above the ceiling throw `RangeError`. Pure-mode signatures are non-streamable by design (`Ed25519Suite` does not implement `StreamableSignatureSuite`, so `SignStream(Ed25519Suite, ...)` is a compile-time error). Larger payloads must use `Ed25519PreHashSuite` (0x11) with `Sign` or `SignStream`; the prehash path computes SHA-512 at the TypeScript layer and only stages the 64-byte digest in WASM.

#### Ed25519PreHashSuite (prehash, Ed25519ph)

`Ed25519PreHashSuite` covers Ed25519ph, RFC 8032 §5.1.7, signature verification. Satisfies `StreamableSignatureSuite` and plugs into `SignStream` / `VerifyStream`. The prehash algorithm is fixed at SHA-512 (`prehashAlgorithm: 'sha-512'`, `prehashSize: 64`); Ed25519ph permits no other hash function per the spec, so there is no parameterization to expose.

The suite binds context through the WASM substrate's dom2(F=1, effective_ctx) prefix. The factory calls `buildEffectiveCtx(ctxDomain, user_ctx)` once per sign or verify and passes the result to `ed25519SignPrehashed` / `ed25519VerifyPrehashed` as the WASM ctx parameter; the substrate hashes `'SigEd25519 no Ed25519 collisions' || 0x01 || |effective_ctx| || effective_ctx` into both SHA-512 inputs that produce r and k.

The message-taking `sign(sk, msg, ctx)` and `verify(pk, msg, sig, ctx)` paths route through `sha512OneShot(msg)` from `src/ts/sign/hasher.ts`, which drives the sha2 WASM module. The streaming path through `SignStream` / `VerifyStream` uses `createRunningHash('sha-512')`, which constructs a buffered shim (`sha512Buffered` in `src/ts/sign/hasher.ts`) over the one-shot `SHA512` class; chunks are copied and concatenated at `finalize()` so the output is byte-identical to a one-shot SHA-512 over the full message. Both paths drive sha2, not the curve25519-embedded SHA-512; the embedded copy covers dom2 prefixing inside the WASM and is not exposed at the ABI.

`Ed25519PreHashSuite.wasmModules` is `['curve25519', 'sha2']` so consumers know to call `init({ ed25519: curve25519Wasm, sha2: sha2Wasm })` (or the equivalent subpath inits) before using the suite. `Ed25519Suite.wasmModules` is `['curve25519']` alone; pure mode does not touch sha2.

#### Fault-injection defense

The fault-injection defence lives on the direct `Ed25519.sign(sk, pk, M)` and `Ed25519.signPrehashed(sk, pk, digest, ctx)` class entry points, where the WASM re-derives pk from sk and aborts via `unreachable` if it does not match the caller-supplied pk. The TypeScript wrapper catches the resulting `WebAssembly.RuntimeError` and rethrows as `SigningError('sig-malformed-input', ...)`. The defence is meaningful only for callers who hold a stored, known-good pk (loaded from disk after a long-term keygen).

The Ed25519 suite consts route through the unexported `_signInternalPk` / `_signPrehashedInternalPk` helpers on the `Ed25519` class, which derive pk inside the same WASM call and skip the cross-check. At the suite call site the comparison would be between two outputs of the same potentially-faulted module on the same call, so the defence collapses to no defence; skipping it saves one basepoint scalar multiplication per sign on the hot path that every `Sign` and `SignStream` invocation traverses. Callers who care about the fault-injection defence should drop down to `Ed25519` directly with their stored pk; callers who are content to derive pk from sk per call (the suite-layer story) accept the same trust boundary as a stored-pk caller who never validated their stored pk.

See [ed25519.md](./ed25519.md#fault-injection-defense) for the underlying threat model and [ed25519_audit.md](./ed25519_audit.md#fault-injection-defense) for the audit checklist.

#### Wire format

Both Ed25519 suites use the standard v3 attached envelope. Per [Attached envelope](#attached-envelope):

```
byte  0                : suite_byte    (0x01 for Ed25519Suite, 0x11 for Ed25519PreHashSuite)
byte  1                : ctx_len       (0 for Ed25519Suite, 0..255 for Ed25519PreHashSuite)
bytes 2 .. 2+ctx_len   : ctx           (raw user_ctx, no domain prefix)
bytes ... payload_end  : payload       (the message)
bytes payload_end .. N : sig           (64 bytes, R || s)
```

`Ed25519Suite` always has `ctx_len = 0` because the suite rejects non-empty user_ctx. `Ed25519PreHashSuite` accepts a per-call `user_ctx` up to 200 bytes (the cap from `src/ts/sign/ctx.ts`, well under the FIPS 204-style 255-byte limit). KAT vectors for both suites live in `test/vectors/sign_ed25519.ts` and verify byte-for-byte against the third-party Ed25519 oracles per [vector_audit.md](./vector_audit.md).

For detached signing, `Sign.signDetached(suite, sk, msg, ctx)` returns exactly 64 bytes (R || s) per RFC 8032 §5.1.6, signature generation; the caller manages `(suite, pk, msg, sig, ctx)` out of band.

### ECDSA-P256 suite

One classical ECDSA suite covers FIPS 186-5 §6, ECDSA Signature Algorithm, over the NIST P-256 curve (SP 800-186 §3.2.1.3, P-256). `EcdsaP256Suite` (`0x02`) signs an SHA-256 prehash of the message with hedged-deterministic RFC 6979 nonce derivation per `draft-irtf-cfrg-det-sigs-with-noise-05`. ECDSA-P256 is classical, not post-quantum, so plan for migration to a classical+PQ hybrid (`0x22` / `0x23`, reserved) when long-horizon assurance matters. See [SECURITY.md](../SECURITY.md) for the threat model. The full ECDSA-P256 reference lives in [ecdsa-p256.md](./ecdsa-p256.md); the audit checklist lives in [ecdsa-p256_audit.md](./ecdsa-p256_audit.md).

| Field              | `EcdsaP256Suite`              |
|--------------------|-------------------------------|
| `formatEnum`       | `0x02`                        |
| `formatName`       | `'ecdsa-p256'`                |
| `ctxDomain`        | `ecdsa-p256-envelope-v3`      |
| `pkSize`           | 33 (SEC 1 §2.3.3 compressed)  |
| `skSize`           | 32                            |
| `sigSize`          | 64 (raw r \|\| s, low-S)      |
| `prehashAlgorithm` | `'sha-256'`                   |
| `prehashSize`      | 32                            |
| `wasmModules`      | `['p256', 'sha2']`            |

#### Single mode with ctx-rejection lock

ECDSA has no native context parameter (FIPS 186-5 §6.4, ECDSA Signature Generation, produces signatures parametrised only by `(d, hash, k)`). The suite carries a built-in `ctxDomain` of `'ecdsa-p256-envelope-v3'` for `formatName` and display purposes, but rejects any non-empty user_ctx with `SigningError('sig-ctx-unsupported')` on every entry point (`sign`, `verify`, `signPrehashed`, `verifyPrehashed`). Applications that need context-bound signing must use a classical+PQ hybrid suite at `0x22` or `0x23` (reserved); the PQ half of those suites carries its own ctxDomain story via FIPS 204 / FIPS 205's native ctx parameter.

Unlike pure Ed25519, ECDSA-P256 conforms to `StreamableSignatureSuite`. Every ECDSA signature internally prehashes the message via SHA-256 (the spec REQUIRES it; ECDSA cannot sign message bytes directly). `SignStream(EcdsaP256Suite, sk, EMPTY_CTX)` is well-defined: the message bytes flow through `sha256Buffered` (from `src/ts/sign/hasher.ts`) into the WASM signature engine which sees only the 32-byte digest. The buffered shim copies and concatenates chunks at `finalize()` so the streamed output's digest is byte-identical to a one-shot SHA-256 over the full message; only the trailing 64-byte signature differs between one-shot and streamed runs over the same `(sk, msg)` because each sign re-rolls hedging entropy.

#### Hedged-by-default

ECDSA's nonce derivation is the most operationally dangerous part of the signature scheme. RFC 6979 §3.2 derives `k` deterministically from `(d, H(m))`; leaking `k` to an attacker lets them recover `d` via the standard ECDSA-with-known-k recovery. Pure-deterministic ECDSA is fully exposed if an attacker can read `d`-derived intermediates across two signatures through a fault-injection channel; hedged ECDSA mixes per-call entropy so each signature has independent nonce-derivation state.

`EcdsaP256Suite.sign` and `EcdsaP256Suite.signPrehashed` generate `rnd = randomBytes(32)` per call, thread it through `EcdsaP256._signInternalPk`, and wipe the buffer in the `finally` block. The hedged construction is `draft-irtf-cfrg-det-sigs-with-noise-05` §4, Hedged-Deterministic Nonce Generation. Two calls to `EcdsaP256Suite.sign(sk, msg, EMPTY_CTX)` over the same `(sk, msg)` return DIFFERENT signatures (the rnd differs). Both verify under the same pk.

Consumers who need byte-deterministic signatures (RFC 6979 §3.2 with empty entropy) must drop down to `EcdsaP256` directly with `rnd = new Uint8Array(32)`. The suite layer does not expose that knob because per-call entropy is the safety-by-default posture for v3 signing.

#### Low-S enforcement

ECDSA has a signature-malleability surface (`(r, s)` and `(r, n - s)` both verify under the same `(pk, msgHash)`). RFC 6979 §3.5 mandates low-S for deterministic ECDSA; the leviathan-crypto suite extends low-S to the hedged path. The WASM signer normalises `s ← min(s, n - s)` before returning; the WASM verifier rejects `s > n/2` before evaluating the signature equation. Wycheproof's `ecdsa_secp256r1_sha256_p1363` corpus exercises every malleability variant and confirms that the strict-gate fires on every spec-defined malleation.

FIPS 186-5 §6.4.4 itself does NOT mandate low-S on verify, so a signature with high-S that fails under `EcdsaP256Suite.verify` might pass under a FIPS 186-5-conformant verifier elsewhere in the ecosystem. The strict-gate posture is leviathan-crypto's choice; see [ecdsa-p256.md §Low-S Enforcement](./ecdsa-p256.md#low-s-enforcement) and [vector_audit.md §ECDSA-P256](./vector_audit.md) for the reconciliation against the ACVP corpus.

#### Fault-injection defense

The fault-injection defence lives on the direct `EcdsaP256.sign(sk, pk, msgHash, rnd)` class entry, where the WASM re-derives pk from sk and aborts via `unreachable` on mismatch against the caller-supplied pk. The TypeScript wrapper catches the resulting `WebAssembly.RuntimeError` and rethrows as `SigningError('sig-malformed-input', ...)`. The defence is meaningful only for callers who hold a stored, known-good pk (loaded from disk after a long-term keygen).

`EcdsaP256Suite` routes through the unexported `_signInternalPk` helper, which derives pk inside the same WASM call and skips the cross-check. At the suite call site the comparison would be between two outputs of the same potentially-faulted module on the same call, so the defence collapses to no defence; skipping it saves one fixed-base scalar multiplication per sign on the hot path that every `Sign` and `SignStream` invocation traverses. Callers who care about the fault-injection defence should drop down to `EcdsaP256` directly with their stored pk; the suite-layer story is identical to Ed25519's.

See [ecdsa-p256.md §Fault-Injection Defense](./ecdsa-p256.md#fault-injection-defense) for the underlying threat model and [ecdsa-p256_audit.md §Fault-Injection Defense](./ecdsa-p256_audit.md#fault-injection-defense) for the audit checklist.

#### Wire format

```
byte  0                : suite_byte    (0x02)
byte  1                : ctx_len       (always 0 for EcdsaP256Suite)
bytes 2 .. payload_end : payload       (the message)
bytes payload_end .. N : sig           (64 bytes, r || s, low-S)
```

`EcdsaP256Suite` always has `ctx_len = 0` because the suite rejects non-empty user_ctx. KAT vectors live in `test/vectors/sign_ecdsa_p256.ts` and verify byte-for-byte against the third-party `p256` + `ecdsa` Rust oracles per [vector_audit.md](./vector_audit.md).

For detached signing, `Sign.signDetached(EcdsaP256Suite, sk, msg, ctx)` returns exactly 64 bytes (`r || s`, low-S) per FIPS 186-5 §6.4, ECDSA Signature Generation; the caller manages `(suite, pk, msg, sig, ctx)` out of band. The DER form is available via `ecdsaSignatureToDer` / `ecdsaSignatureFromDer` (RFC 3279 §2.2.3) for X.509 / JWS / TLS interop.

### SLH-DSA pure-mode suites

The SLH-DSA pure-mode suites cover FIPS 205 §10.1. They satisfy `SignatureSuite` only.

| Field         | `SlhDsa128fSuite`         | `SlhDsa192fSuite`         | `SlhDsa256fSuite`         |
|---------------|---------------------------|---------------------------|---------------------------|
| `formatEnum`  | `0x06`                    | `0x07`                    | `0x08`                    |
| `formatName`  | `'slhdsa128f'`            | `'slhdsa192f'`            | `'slhdsa256f'`            |
| `ctxDomain`   | `slhdsa128f-envelope-v3`  | `slhdsa192f-envelope-v3`  | `slhdsa256f-envelope-v3`  |
| `pkSize`      | 32                        | 48                        | 64                        |
| `skSize`      | 64                        | 96                        | 128                       |
| `sigSize`     | 17088                     | 35664                     | 49856                     |
| `wasmModules` | `['slhdsa']`              | `['slhdsa']`              | `['slhdsa']`              |

Pick `SlhDsa192fSuite` (category 3) as a general-purpose default. `SlhDsa128fSuite` is the smallest hash-based signature available; `SlhDsa256fSuite` is the highest assurance variant for long-lived keys. See [slhdsa.md](./slhdsa.md) for the underlying SLH-DSA reference, including the FIPS 205 §3.4 hedged-versus-deterministic discussion and the wipe discipline.

### SLH-DSA prehash-mode suites

| Field              | `SlhDsa128fPreHashSuite`              | `SlhDsa192fPreHashSuite`              | `SlhDsa256fPreHashSuite`              |
|--------------------|---------------------------------------|---------------------------------------|---------------------------------------|
| `formatEnum`       | `0x16`                                | `0x17`                                | `0x18`                                |
| `formatName`       | `'slhdsa128f-prehash'`                | `'slhdsa192f-prehash'`                | `'slhdsa256f-prehash'`                |
| `ctxDomain`        | `slhdsa128f-prehash-envelope-v3`      | `slhdsa192f-prehash-envelope-v3`      | `slhdsa256f-prehash-envelope-v3`      |
| `pkSize`           | 32                                    | 48                                    | 64                                    |
| `skSize`           | 64                                    | 96                                    | 128                                   |
| `sigSize`          | 17088                                 | 35664                                 | 49856                                 |
| `prehashAlgorithm` | `'shake-128'`                         | `'shake-256'`                         | `'shake-256'`                         |
| `prehashSize`      | 32                                    | 64                                    | 64                                    |
| `wasmModules`      | `['slhdsa', 'sha3']`                  | `['slhdsa', 'sha3']`                  | `['slhdsa', 'sha3']`                  |

The prehash choice tracks FIPS 205 §10.2.2's category restriction: SHAKE128 is only appropriate for category 1, so `SlhDsa128fPreHashSuite` pins it; SHAKE256 covers categories 3 and 5, so `SlhDsa192fPreHashSuite` and `SlhDsa256fPreHashSuite` pin it. The category gate is enforced at the underlying primitive's public surface; calling these suites with the wrong prehash is impossible because each suite has its prehash baked in.

### PQ-only hybrid suites

The three hybrid suites compose ML-DSA with SLH-DSA at each NIST security category. They satisfy `StreamableSignatureSuite` and produce a single combined signature that an attacker would have to forge under both primitives. See [PQ-only hybrid composite encoding](#pq-only-hybrid-composite-encoding) below for the wire format and threat model.

| Field              | `MlDsa44SlhDsa128fSuite`              | `MlDsa65SlhDsa192fSuite`              | `MlDsa87SlhDsa256fSuite`              |
|--------------------|---------------------------------------|---------------------------------------|---------------------------------------|
| `formatEnum`       | `0x30`                                | `0x31`                                | `0x32`                                |
| `formatName`       | `'mldsa44-slhdsa128f'`                | `'mldsa65-slhdsa192f'`                | `'mldsa87-slhdsa256f'`                |
| `ctxDomain`        | `mldsa44-slhdsa128f-envelope-v3`      | `mldsa65-slhdsa192f-envelope-v3`      | `mldsa87-slhdsa256f-envelope-v3`      |
| `pkSize`           | 1344                                  | 2000                                  | 2656                                  |
| `skSize`           | 2624                                  | 4128                                  | 5024                                  |
| `sigSize`          | 19508                                 | 38973                                 | 54483                                 |
| `prehashAlgorithm` | `'shake-128'`                         | `'shake-256'`                         | `'shake-256'`                         |
| `prehashSize`      | 32                                    | 64                                    | 64                                    |
| `wasmModules`      | `['mldsa', 'sha3', 'slhdsa']`         | `['mldsa', 'sha3', 'slhdsa']`         | `['mldsa', 'sha3', 'slhdsa']`         |

Sizes are additive: `pkSize`, `skSize`, and `sigSize` are the sum of the per-primitive sizes from [mldsa.md](./mldsa.md#parameter-sets) and [slhdsa.md](./slhdsa.md#parameter-sets), with ML-DSA in the upper half of the wire and SLH-DSA in the lower half.

---

## PQ-only hybrid composite encoding

The PQ-only hybrid suites (`0x30`, `0x31`, `0x32`) compose ML-DSA with SLH-DSA at each NIST security category. The wire format is leviathan-defined; the IETF `draft-ietf-lamps-pq-composite-sigs` covers classical+PQ pairs only, so it does not apply here. The reserved classical+PQ hybrids (`0x20`-`0x23`) will use the composite-sigs encoding when they ship.

### Wire format

The hybrid encodes its key pair and signature as straight concatenation, ML-DSA half first:

```
pk_combined  = pk_mldsa  || pk_slhdsa
sk_combined  = sk_mldsa  || sk_slhdsa
sig_combined = sig_mldsa || sig_slhdsa
```

No length prefix sits between the halves. Each suite's `pkSize`, `skSize`, and `sigSize` is the sum of the two underlying primitives' sizes from the FIPS 204 / FIPS 205 catalogs, so a receiver that already knows the suite (`formatEnum`) can slice the halves at byte offsets fixed by the catalog. The split offset on the wire is `mldsaParams.pkBytes` for pk, `mldsaParams.skBytes` for sk, `mldsaParams.sigBytes` for sig.

| Suite                       | ML-DSA pk | SLH-DSA pk | pk total | ML-DSA sk | SLH-DSA sk | sk total | ML-DSA sig | SLH-DSA sig | sig total |
|-----------------------------|-----------|------------|----------|-----------|------------|----------|------------|-------------|-----------|
| `MlDsa44SlhDsa128fSuite`    | 1312      | 32         | 1344     | 2560      | 64         | 2624     | 2420       | 17088       | 19508     |
| `MlDsa65SlhDsa192fSuite`    | 1952      | 48         | 2000     | 4032      | 96         | 4128     | 3309       | 35664       | 38973     |
| `MlDsa87SlhDsa256fSuite`    | 2592      | 64         | 2656     | 4896      | 128        | 5024     | 4627       | 49856       | 54483     |

The combined signature lives inside the same attached / detached envelope the ML-DSA suites use; the envelope's `suite_byte` distinguishes a hybrid from a single-primitive signature, and the rest of the wire layout (ctx, payload, sig) follows the [Attached envelope](#attached-envelope) shape with `sigSize` taken from the hybrid suite.

### Prehash and M' construction

Both halves sign the same prehash digest under the same `effective_ctx`. The streaming-and-bundled path computes one digest, passes it to both `signHashPrehashed` calls, then concatenates the two resulting signatures.

The hybrid prehash configuration matches the per-half FIPS 205 §10.2.2 category gate:

| Suite                       | Prehash algorithm | Digest size |
|-----------------------------|-------------------|-------------|
| `MlDsa44SlhDsa128fSuite`    | `shake-128`       | 32 bytes    |
| `MlDsa65SlhDsa192fSuite`    | `shake-256`       | 64 bytes    |
| `MlDsa87SlhDsa256fSuite`    | `shake-256`       | 64 bytes    |

The two M' constructions are byte-identical across the two primitives. FIPS 204 §5.4 Algorithm 4 builds `M' = 0x01 || |ctx| || ctx || OID(ph) || PH_M`, and FIPS 205 §10.2.2 Algorithm 23 builds the same string. The SHAKE OIDs are registered on the same NIST CSOR branch in both specs (FIPS 204 §5.4.1 = FIPS 205 §10.2.2), so the OID bytes match byte-for-byte. ML-DSA's domain-separator byte is `0x01` and SLH-DSA's is also `0x01` for HashML-DSA / HashSLH-DSA, so both halves see exactly the same M' when called with the same `(digest, ph, ctx)`.

The two primitives still produce different signatures because their internal algorithms are different: ML-DSA's signing reduces to lattice arithmetic over the M' digest while SLH-DSA's signing reduces to hash-based authentication paths over the same digest. The attacker faces two distinct hard problems, both binding the same M'.

### Domain separation

Each hybrid suite carries a unique `ctxDomain`:

- `mldsa44-slhdsa128f-envelope-v3`
- `mldsa65-slhdsa192f-envelope-v3`
- `mldsa87-slhdsa256f-envelope-v3`

The hybrid factory passes this `ctxDomain` into `buildEffectiveCtx(ctxDomain, user_ctx)` once and reuses the result for both `signHashPrehashed` calls. Because the same `effective_ctx` reaches both primitives, a forgery against one half is bound to the hybrid's domain, not to a standalone ML-DSA or SLH-DSA suite. Specifically:

- Cross-suite forgery is prevented. An ML-DSA half signed under `mldsa44-envelope-v3` (standalone `MlDsa44Suite`) does NOT verify as the ML-DSA half of the hybrid `0x30` because the `effective_ctx` differs at the byte level.
- Cross-hybrid forgery is prevented. The ML-DSA half of `0x30` does NOT verify as the ML-DSA half of `0x31` because the suites' `ctxDomain` strings differ.

No per-half `ctxDomain` suffix is needed. ML-DSA pk and SLH-DSA pk are distinct artifacts (different sizes, different formats), so a sig produced for one primitive cannot accidentally verify under the other's pk regardless of `ctxDomain`. The hybrid-level uniqueness is sufficient.

### Threat model summary

PQ-only hybrids defend against the case where one PQ family is broken before the other. If ML-DSA falls to a lattice cryptanalysis advance, the SLH-DSA half holds (an attacker still has to invert SHAKE256 to forge it). If SLH-DSA falls (a SHAKE256 weakness or a structural break in the hypertree), the ML-DSA half holds. The combined signature is secure iff at least one half is unbroken. See [SECURITY.md](../SECURITY.md#pq-only-hybrid-signature-threat-model) for the full threat model including what hybrids do NOT defend against.

### Sign / verify pseudocode

`Sign.sign` and `Sign.verify` route through the hybrid suite's `signPrehashed` / `verifyPrehashed`. The two methods take a precomputed digest; the streaming path (`SignStream` / `VerifyStream`) drives the digest computation internally via the suite's pinned `prehashAlgorithm`.

```text
suite.signPrehashed(sk, digest, ctx):
    require digest.length == prehashSize
    require sk.length     == skSize
    effective_ctx = buildEffectiveCtx(suite.ctxDomain, ctx)
    sk_mldsa      = sk[0 .. mldsaParams.skBytes]
    sk_slhdsa     = sk[mldsaParams.skBytes .. ]
    sig_mldsa     = MlDsaX.signHashPrehashed(sk_mldsa, digest, ph, effective_ctx)
    sig_slhdsa    = SlhDsaY.signHashPrehashed(sk_slhdsa, digest, ph, effective_ctx)
    return sig_mldsa || sig_slhdsa
```

```text
suite.verifyPrehashed(pk, digest, sig, ctx):
    if pk.length     != pkSize:      return false
    if sig.length    != sigSize:     return false
    if digest.length != prehashSize: return false
    effective_ctx = buildEffectiveCtx(suite.ctxDomain, ctx)
    pk_mldsa   = pk[0 .. mldsaParams.pkBytes]
    pk_slhdsa  = pk[mldsaParams.pkBytes .. ]
    sig_mldsa  = sig[0 .. mldsaParams.sigBytes]
    sig_slhdsa = sig[mldsaParams.sigBytes .. ]
    mldsa_ok   = MlDsaX.verifyHashPrehashed (pk_mldsa,  digest, sig_mldsa,  ph, effective_ctx)
    slhdsa_ok  = SlhDsaY.verifyHashPrehashed(pk_slhdsa, digest, sig_slhdsa, ph, effective_ctx)
    return mldsa_ok AND slhdsa_ok
```

Notice that both `verifyHashPrehashed` calls run unconditionally before the `AND` reduction. The next subsection covers why.

### Constant-time discipline

`verifyPrehashed` always runs both sub-verifies regardless of intermediate boolean outcomes. The reference implementation declares `mldsaOk` and `slhdsaOk` without initial values so neither variable is readable until both sub-verifies have completed. The trailing `mldsa_ok AND slhdsa_ok` is a boolean AND on values that have already been computed, so JavaScript's short-circuit operator has nothing to short-circuit: total work is the sum of the two sub-verifies regardless of which (if either) fails. Each sub-verify is itself constant-time on attacker-supplied bytes per its FIPS contract. A timing observer cannot distinguish an ML-DSA failure from an SLH-DSA failure from a both-failed case.

The suite never wipes caller-supplied buffers, including `sigMldsa` and `sigSlhdsa` (which are subarray views over the caller's `sig`). The lib-allocated `effective_ctx` is wiped in `finally`.

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

`sig-suite-unknown` is reserved for a future routing API that resolves the suite from the wire byte; callers always pass the suite explicitly today, so the discriminator never fires here.

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

The ML-DSA prehash suites use `'sha3-256'` and `'sha3-512'`. The remaining values are reserved for future suites.

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

The wire `ctx_len` field is `u8`, so `user_ctx` is additionally capped at 255 on the wire. The suite layer uses the smaller 200-byte cap for ergonomic headroom under the FIPS 204 limit.

### Naming convention

Suite `ctxDomain` values follow a simple pattern.

- Pure-mode suites: `{scheme}-envelope-v3`.
- Prehash-mode suites: `{scheme}-prehash-envelope-v3`.

Hybrid suites use `{outer}-{inner}-envelope-v3`; see the format byte allocation table for the full list.

---

## Errors

Every signing-layer failure throws `SigningError(discriminator, message?)`. The discriminator is the stable, machine-readable identifier; the message is a human-readable string with context. The discriminators below are organized by layer.

| Discriminator           | Layer             | Trigger |
|-------------------------|-------------------|---------|
| `sig-key-size`          | suite             | Wrong-length sk or pk for the suite. |
| `sig-ctx-too-long`      | suite             | `user_ctx` exceeds 200 bytes. |
| `sig-ctx-unsupported`   | suite             | Non-empty `user_ctx` passed to a suite with no native context parameter (`Ed25519Suite`, pure-mode 0x01). Pure RFC 8032 §5.1.6 Ed25519 has no ctx; context-bound signing must use `Ed25519PreHashSuite` (0x11) via dom2(F=1, ctx). Future pure-only suites (e.g. Ed448) reuse the same discriminator. |
| `sig-malformed-input`   | suite             | Primitive validation failure, for example a wrong-length digest in `signPrehashed` or `verifyPrehashed` (both throw symmetrically). |
| `sig-blob-too-short`    | envelope          | `Sign.verify` blob shorter than `2 + suite.sigSize`. |
| `sig-suite-unknown`     | envelope          | Wire `suite_byte` is not in the catalog. Reserved; callers pass the suite explicitly today, so this discriminator does not fire. |
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

The full 22-entry catalog. Shipped rows are wired and tested today; queued rows reserve the wire byte for future work.

| Byte | Suite                       | Mode    | Prehash               | ctxDomain                          | Status   |
|------|-----------------------------|---------|-----------------------|------------------------------------|----------|
| 0x01 | `Ed25519Suite`              | pure    | -                     | `ed25519-envelope-v3`              | shipped  |
| 0x02 | `EcdsaP256Suite`            | single  | SHA-256               | `ecdsa-p256-envelope-v3`           | shipped  |
| 0x03 | `MlDsa44Suite`              | pure    | -                     | `mldsa44-envelope-v3`              | shipped  |
| 0x04 | `MlDsa65Suite`              | pure    | -                     | `mldsa65-envelope-v3`              | shipped  |
| 0x05 | `MlDsa87Suite`              | pure    | -                     | `mldsa87-envelope-v3`              | shipped  |
| 0x06 | `SlhDsa128fSuite`           | pure    | -                     | `slhdsa128f-envelope-v3`           | shipped  |
| 0x07 | `SlhDsa192fSuite`           | pure    | -                     | `slhdsa192f-envelope-v3`           | shipped  |
| 0x08 | `SlhDsa256fSuite`           | pure    | -                     | `slhdsa256f-envelope-v3`           | shipped  |
| 0x11 | `Ed25519PreHashSuite`       | prehash | SHA-512 (Ed25519ph)   | `ed25519-prehash-envelope-v3`      | shipped  |
| 0x13 | `MlDsa44PreHashSuite`       | prehash | SHA3-256              | `mldsa44-prehash-envelope-v3`      | shipped  |
| 0x14 | `MlDsa65PreHashSuite`       | prehash | SHA3-256              | `mldsa65-prehash-envelope-v3`      | shipped  |
| 0x15 | `MlDsa87PreHashSuite`       | prehash | SHA3-512              | `mldsa87-prehash-envelope-v3`      | shipped  |
| 0x16 | `SlhDsa128fPreHashSuite`    | prehash | SHAKE-128             | `slhdsa128f-prehash-envelope-v3`   | shipped  |
| 0x17 | `SlhDsa192fPreHashSuite`    | prehash | SHAKE-256             | `slhdsa192f-prehash-envelope-v3`   | shipped  |
| 0x18 | `SlhDsa256fPreHashSuite`    | prehash | SHAKE-256             | `slhdsa256f-prehash-envelope-v3`   | shipped  |
| 0x20 | `MlDsa44Ed25519Suite`       | hybrid  | SHA-512               | `mldsa44-ed25519-envelope-v3`      | queued   |
| 0x21 | `MlDsa65Ed25519Suite`       | hybrid  | SHA-512               | `mldsa65-ed25519-envelope-v3`      | queued   |
| 0x22 | `MlDsa44EcdsaP256Suite`     | hybrid  | SHA-256               | `mldsa44-ecdsa-p256-envelope-v3`   | queued   |
| 0x23 | `MlDsa65EcdsaP256Suite`     | hybrid  | SHA-512               | `mldsa65-ecdsa-p256-envelope-v3`   | queued   |
| 0x30 | `MlDsa44SlhDsa128fSuite`    | hybrid  | SHAKE-128             | `mldsa44-slhdsa128f-envelope-v3`   | shipped  |
| 0x31 | `MlDsa65SlhDsa192fSuite`    | hybrid  | SHAKE-256             | `mldsa65-slhdsa192f-envelope-v3`   | shipped  |
| 0x32 | `MlDsa87SlhDsa256fSuite`    | hybrid  | SHAKE-256             | `mldsa87-slhdsa256f-envelope-v3`   | shipped  |

22 of 64 slots used. Reserved capacity covers Ed448, ECDSA-P384, brainpool curves, FROST suites, ML-DSA-87 classical hybrids, and threshold variants.

The classical+PQ hybrid bytes (`0x20-0x23`) follow the composite-sigs draft `HashMLDSA{44,65}-{Ed25519,ECDSA-P256}-{SHA256,SHA512}` encoding. The PQ-only hybrid bytes (`0x30-0x32`) are leviathan-flavored; see the [PQ-only hybrid composite encoding](#pq-only-hybrid-composite-encoding) section above for the full wire layout, prehash alignment, and constant-time discipline.

---

## Custom suites

`SignatureSuite` is a TypeScript interface, not a sealed class. A consumer can satisfy the interface and pass a custom suite to `Sign`, `SignStream`, and `VerifyStream`. The catalog format bytes are reserved by the library, so a custom suite must pick a `formatEnum` outside the allocated range. No specific custom-suite range is reserved today; if you need one, raise an issue.

Custom suites do not get the factory helpers the in-tree suites use. You are responsible for the per-call WASM lifecycle, the `ctxDomain` cap, the `effective_ctx` construction, and the per-method wipe discipline. Read `src/ts/sign/suites/mldsa.ts` before writing one; the mldsa-suites factory captures every invariant the in-tree suites satisfy.

---

## Threat model

### Pure versus prehash

Pure-mode suites bind the full message bytes inside FIPS 204's M' construction (`M' = 0x00 ‖ |ctx| ‖ ctx ‖ M`). Prehash-mode suites compose with FIPS 204 §5.4 HashML-DSA, which substitutes `M' = 0x01 ‖ |ctx| ‖ ctx ‖ OID(ph) ‖ Hash(M, ph)`. The domain-separator byte differs (`0x00` vs `0x01`), so a signature produced in one mode never verifies in the other on the same key.

Pure mode offers the larger collision-resistance margin because the signature binds the message bytes themselves. Prehash mode is necessary when the application cannot buffer `M`; the streaming layer in this library uses it for that reason.

### Classical+PQ hybrid (reserved, `0x2X`)

Classical+PQ hybrids defend against the case where the PQ assumption (M-LWE for ML-DSA) is broken before a CRQC arrives. The classical half (Ed25519 or ECDSA-P256) keeps signatures unforgeable in that world. These hybrids do not defend against a CRQC adversary; the classical half falls to Shor's algorithm. Ship them when you need ecosystem interop or PKI migration, not when the threat model assumes a future CRQC.

### PQ-only hybrid (`0x3X`)

PQ-only hybrids defend against the case where one PQ family is broken while the other holds. ML-DSA pairs with SLH-DSA, which rests on a different cryptanalytic foundation (hash-based, no lattice assumption). Neither half falls to Shor's algorithm; Grover's quadratic speedup only halves SLH-DSA's bit security, well above its design margin. Pick PQ-only hybrids when you need "this signature must verify in 2050."

See the [PQ-only hybrid composite encoding](#pq-only-hybrid-composite-encoding) section above for the wire format and constant-time discipline, and [SECURITY.md](../SECURITY.md#pq-only-hybrid-signature-threat-model) for the full threat model including what these hybrids do NOT defend against.

The library carries both hybrid families because consumer threat models differ. Classical hybrids serve adoption and interop; PQ-only hybrids serve long-horizon assurance.

---

## Cross-references

| Document | Description |
|----------|-------------|
| [README](./README.md) | Documentation index |
| [architecture](./architecture.md) | Module overview, build pipeline, and three-tier design |
| [ciphersuite](./ciphersuite.md) | Symmetric / AEAD counterpart to this document |
| [mldsa](./mldsa.md) | Underlying ML-DSA reference, including `signHashPrehashed` and the FIPS 204 §5.4 prehash family |
| [slhdsa](./slhdsa.md) | Underlying SLH-DSA reference, including `signHashPrehashed` and the FIPS 205 §10.2.2 prehash family |
| [SECURITY.md](../SECURITY.md) | Project security policy and the PQ-only hybrid threat model |
| [aead](./aead.md) | `Seal`, `SealStream`, `OpenStream` (parallel encryption surface) |
| [errors](./exports.md) | `SigningError` and `AuthenticationError` export reference |
| [types](./types.md) | TypeScript interfaces |

External references:

- FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA), 2024.
- FIPS 205: Stateless Hash-Based Digital Signature Standard (SLH-DSA), 2024.
- FIPS 186-5: Digital Signature Standard (DSS), 2023 (ECDSA).
- RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA).
- `draft-ietf-lamps-pq-composite-sigs`: Composite ML-DSA hybrid encodings.
