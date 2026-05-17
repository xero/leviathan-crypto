<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### SignatureSuite

The extension point for the v3 signing layer. `Sign`, `SignStream`, and `VerifyStream` are scheme-agnostic. You provide the signing scheme by passing a `SignatureSuite` object at each call site or to the stream constructors.

---

> ### Table of Contents
> - [Implementations included](#implementations-included)
> - [Pure-mode suites](#pure-mode-suites)
> - [Prehash-mode suites](#prehash-mode-suites)
> - [PQ-only hybrid composite encoding](#pq-only-hybrid-composite-encoding)
> - [Classical+PQ hybrid composite encoding](#classicalpq-hybrid-composite-encoding)
> - [Wire format](#wire-format)
> - [Interface reference](#interface-reference)
> - [ctx-domain construction](#ctx-domain-construction)
> - [Errors](#errors)
> - [Examples](#examples)
> - [Memory hygiene](#memory-hygiene)
> - [Format byte allocation](#format-byte-allocation)
> - [Custom suites](#custom-suites)
> - [Threat model](#threat-model)
> - [Cross-References](#cross-references)

---

## Implementations included

Six ML-DSA suites ship. Three are pure-mode, satisfying `SignatureSuite`; three are prehash-mode, satisfying `StreamableSignatureSuite` and usable with `SignStream` / `VerifyStream`.

SLH-DSA (FIPS 205) and the leviathan PQ-only hybrids also ship: six SLH-DSA suites (three pure, three prehash) plus three hybrid composites that combine ML-DSA with SLH-DSA at each NIST security category. Two Ed25519 suites ship (pure plus Ed25519ph). One ECDSA-P256 suite ships (`EcdsaP256Suite`, FIPS 186-5 §6 over NIST P-256 with SHA-256, hedged-by-default per `draft-irtf-cfrg-det-sigs-with-noise-05`). Four composite classical+PQ hybrid suites ship at format bytes `0x20`-`0x23`, implementing `draft-ietf-lamps-pq-composite-sigs` composite ML-DSA with Ed25519 or ECDSA-P256 at the matching NIST categories. Reserved for future work: BLAKE3-derived signature work and the Merkle log signed-tree-head surface that wires the same `SignatureSuite` shape into log proofs. The format-byte allocation at the bottom of this doc reserves a wire byte for every catalog entry, shipped or queued.

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
| `sigMaxSize`  | 2420                   | 3309                   | 4627                   |
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
| `sigMaxSize`       | 2420                               | 3309                               | 4627                               |
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

Two classical Ed25519 suites cover RFC 8032 §5.1, Ed25519. `Ed25519Suite` (`0x01`) signs the message bytes directly in pure mode; `Ed25519PreHashSuite` (`0x11`) signs an SHA-512 prehash with the dom2(F=1, ctx) binding. Ed25519 is classical, not post-quantum, so plan for migration to the composite classical+PQ hybrids `MlDsa44Ed25519Suite` (`0x20`) or `MlDsa65Ed25519Suite` (`0x21`) when long-horizon assurance matters. See [SECURITY.md](../SECURITY.md) for the threat model. The full Ed25519 reference lives in [ed25519.md](./ed25519.md); the audit checklist lives in [ed25519_audit.md](./ed25519_audit.md).

| Field              | `Ed25519Suite`         | `Ed25519PreHashSuite`              |
|--------------------|------------------------|------------------------------------|
| `formatEnum`       | `0x01`                 | `0x11`                             |
| `formatName`       | `'ed25519'`            | `'ed25519-prehash'`                |
| `ctxDomain`        | `ed25519-envelope-v3`  | `ed25519-prehash-envelope-v3`      |
| `pkSize`           | 32                     | 32                                 |
| `skSize`           | 32                     | 32                                 |
| `sigMaxSize`       | 64                     | 64                                 |
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
byte  0                              : suite_byte    (0x01 for Ed25519Suite, 0x11 for Ed25519PreHashSuite)
byte  1                              : ctx_len       (0 for Ed25519Suite, 0..255 for Ed25519PreHashSuite)
bytes 2 .. 2+ctx_len                 : ctx           (raw user_ctx, no domain prefix)
bytes 2+ctx_len .. 2+ctx_len+4       : payload_len   (u32 big-endian)
bytes 2+ctx_len+4 .. payload_end     : payload       (exactly payload_len bytes)
bytes payload_end .. N               : sig           (64 bytes, R || s)
```

`Ed25519Suite` always has `ctx_len = 0` because the suite rejects non-empty user_ctx. `Ed25519PreHashSuite` accepts a per-call `user_ctx` up to `USER_CTX_MAX` (255 bytes), matching the FIPS 204 §3.6.1 native ctx cap. The combined-ctx check in `buildEffectiveCtx` lowers the effective ceiling to 226 bytes for this suite (253 minus the 27-byte `ed25519-prehash-envelope-v3` domain). KAT vectors for both suites live in `test/vectors/sign_ed25519.ts` and verify byte-for-byte against the third-party Ed25519 oracles per [vector_audit.md](./vector_audit.md).

For detached signing, `Sign.signDetached(suite, sk, msg, ctx)` returns exactly 64 bytes (R || s) per RFC 8032 §5.1.6, signature generation; the caller manages `(suite, pk, msg, sig, ctx)` out of band.

### ECDSA-P256 suite

One classical ECDSA suite covers FIPS 186-5 §6, ECDSA Signature Algorithm, over the NIST P-256 curve (SP 800-186 §3.2.1.3, P-256). `EcdsaP256Suite` (`0x02`) signs an SHA-256 prehash of the message with hedged-deterministic RFC 6979 nonce derivation per `draft-irtf-cfrg-det-sigs-with-noise-05`. ECDSA-P256 is classical, not post-quantum, so plan for migration to the composite classical+PQ hybrids `MlDsa44EcdsaP256Suite` (`0x22`) or `MlDsa65EcdsaP256Suite` (`0x23`) when long-horizon assurance matters. See [SECURITY.md](../SECURITY.md) for the threat model. The full ECDSA-P256 reference lives in [ecdsa-p256.md](./ecdsa-p256.md); the audit checklist lives in [ecdsa-p256_audit.md](./ecdsa-p256_audit.md).

| Field              | `EcdsaP256Suite`              |
|--------------------|-------------------------------|
| `formatEnum`       | `0x02`                        |
| `formatName`       | `'ecdsa-p256'`                |
| `ctxDomain`        | `ecdsa-p256-envelope-v3`      |
| `pkSize`           | 33 (SEC 1 §2.3.3 compressed)  |
| `skSize`           | 32                            |
| `sigMaxSize`       | 64 (raw r \|\| s, low-S)      |
| `prehashAlgorithm` | `'sha-256'`                   |
| `prehashSize`      | 32                            |
| `wasmModules`      | `['p256', 'sha2']`            |

#### Single mode with ctx-rejection lock

ECDSA has no native context parameter (FIPS 186-5 §6.4, ECDSA Signature Generation, produces signatures parametrised only by `(d, hash, k)`). The suite carries a built-in `ctxDomain` of `'ecdsa-p256-envelope-v3'` for `formatName` and display purposes, but rejects any non-empty user_ctx with `SigningError('sig-ctx-unsupported')` on every entry point (`sign`, `verify`, `signPrehashed`, `verifyPrehashed`). Applications that need context-bound signing must use `MlDsa44EcdsaP256Suite` (`0x22`) or `MlDsa65EcdsaP256Suite` (`0x23`); those suites bind the caller's `user_ctx` through the composite-sigs §3.2 `M' = Prefix || Label || len(ctx) || ctx || PH(M)` construction.

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
byte  0                              : suite_byte    (0x02)
byte  1                              : ctx_len       (always 0 for EcdsaP256Suite)
bytes 2 .. 2+4                       : payload_len   (u32 big-endian)
bytes 6 .. payload_end               : payload       (exactly payload_len bytes)
bytes payload_end .. N               : sig           (64 bytes, r || s, low-S)
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
| `sigMaxSize`  | 17088                     | 35664                     | 49856                     |
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
| `sigMaxSize`       | 17088                                 | 35664                                 | 49856                                 |
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
| `sigMaxSize`       | 19508                                 | 38973                                 | 54483                                 |
| `prehashAlgorithm` | `'shake-128'`                         | `'shake-256'`                         | `'shake-256'`                         |
| `prehashSize`      | 32                                    | 64                                    | 64                                    |
| `wasmModules`      | `['mldsa', 'sha3', 'slhdsa']`         | `['mldsa', 'sha3', 'slhdsa']`         | `['mldsa', 'sha3', 'slhdsa']`         |

Sizes are additive: `pkSize`, `skSize`, and `sigMaxSize` are the sum of the per-primitive sizes from [mldsa.md](./mldsa.md#parameter-sets) and [slhdsa.md](./slhdsa.md#parameter-sets), with ML-DSA in the upper half of the wire and SLH-DSA in the lower half.

---

## PQ-only hybrid composite encoding

The PQ-only hybrid suites (`0x30`, `0x31`, `0x32`) compose ML-DSA with SLH-DSA at each NIST security category. The wire format is leviathan-defined; the IETF `draft-ietf-lamps-pq-composite-sigs` covers classical+PQ pairs only, so it does not apply here. The classical+PQ hybrids (`0x20`-`0x23`) use the composite-sigs encoding instead; their wire format and M' construction live below under [Classical+PQ hybrid composite encoding](#classicalpq-hybrid-composite-encoding).

### Wire format

The hybrid encodes its key pair and signature as straight concatenation, ML-DSA half first:

```
pk_combined  = pk_mldsa  || pk_slhdsa
sk_combined  = sk_mldsa  || sk_slhdsa
sig_combined = sig_mldsa || sig_slhdsa
```

No length prefix sits between the halves. Each suite's `pkSize`, `skSize`, and `sigMaxSize` is the sum of the two underlying primitives' sizes from the FIPS 204 / FIPS 205 catalogs, so a receiver that already knows the suite (`formatEnum`) can slice the halves at byte offsets fixed by the catalog. The split offset on the wire is `mldsaParams.pkBytes` for pk, `mldsaParams.skBytes` for sk, `mldsaParams.sigBytes` for sig.

| Suite                       | ML-DSA pk | SLH-DSA pk | pk total | ML-DSA sk | SLH-DSA sk | sk total | ML-DSA sig | SLH-DSA sig | sig total |
|-----------------------------|-----------|------------|----------|-----------|------------|----------|------------|-------------|-----------|
| `MlDsa44SlhDsa128fSuite`    | 1312      | 32         | 1344     | 2560      | 64         | 2624     | 2420       | 17088       | 19508     |
| `MlDsa65SlhDsa192fSuite`    | 1952      | 48         | 2000     | 4032      | 96         | 4128     | 3309       | 35664       | 38973     |
| `MlDsa87SlhDsa256fSuite`    | 2592      | 64         | 2656     | 4896      | 128        | 5024     | 4627       | 49856       | 54483     |

The combined signature lives inside the same attached / detached envelope the ML-DSA suites use; the envelope's `suite_byte` distinguishes a hybrid from a single-primitive signature, and the rest of the wire layout (ctx, payload_len, payload, sig) follows the [Attached envelope](#attached-envelope) shape with `sigMaxSize` taken from the hybrid suite.

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
    if sig.length    != sigMaxSize:  return false
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

## Classical+PQ hybrid composite encoding

The classical+PQ hybrid suites (`0x20`-`0x23`) implement `draft-ietf-lamps-pq-composite-sigs` Composite ML-DSA, pairing each ML-DSA parameter set with Ed25519 or ECDSA-P256. The composite combiner runs the user message through a per-suite pre-hash function, wraps the digest in a fixed-prefix `M'` construction that binds the suite identity and the caller-supplied `user_ctx`, then signs `M'` with both sub-signers. Both halves verify independently; the combined result is secure as long as either half is unforgeable.

See `https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/` for the IETF draft.

| Field              | `MlDsa44Ed25519Suite`              | `MlDsa65Ed25519Suite`              | `MlDsa44EcdsaP256Suite`            | `MlDsa65EcdsaP256Suite`            |
|--------------------|------------------------------------|------------------------------------|------------------------------------|------------------------------------|
| `formatEnum`       | `0x20`                             | `0x21`                             | `0x22`                             | `0x23`                             |
| `formatName`       | `'mldsa44-ed25519'`                | `'mldsa65-ed25519'`                | `'mldsa44-ecdsa-p256'`             | `'mldsa65-ecdsa-p256'`             |
| `ctxDomain`        | `mldsa44-ed25519-envelope-v3`      | `mldsa65-ed25519-envelope-v3`      | `mldsa44-ecdsa-p256-envelope-v3`   | `mldsa65-ecdsa-p256-envelope-v3`   |
| `pkSize`           | 1344                               | 1984                               | 1377                               | 2017                               |
| `skSize`           | 64                                 | 64                                 | 83                                 | 83                                 |
| `sigMaxSize`       | 2484                               | 3373                               | 2492 (upper bound)                 | 3381 (upper bound)                 |
| `prehashAlgorithm` | `'sha-512'`                        | `'sha-512'`                        | `'sha-256'`                        | `'sha-512'`                        |
| `prehashSize`      | 64                                 | 64                                 | 32                                 | 64                                 |
| `wasmModules`      | `['mldsa', 'sha3', 'curve25519', 'sha2']` | `['mldsa', 'sha3', 'curve25519', 'sha2']` | `['mldsa', 'sha3', 'p256', 'sha2']` | `['mldsa', 'sha3', 'p256', 'sha2']` |

### Component algorithms

Pinned per composite-sigs §6, Algorithm Identifiers and Parameters.

| Byte | Suite                       | ML-DSA component | Classical component | PH algorithm | OID                |
|------|-----------------------------|------------------|---------------------|--------------|--------------------|
| 0x20 | `MlDsa44Ed25519Suite`       | ML-DSA-44 (FIPS 204 §4 Table 1) | Ed25519 (RFC 8032 §5.1) | SHA-512 (FIPS 180-4 §6.4) | `1.3.6.1.5.5.7.6.39` (`id-MLDSA44-Ed25519-SHA512`) |
| 0x21 | `MlDsa65Ed25519Suite`       | ML-DSA-65 (FIPS 204 §4 Table 1) | Ed25519 (RFC 8032 §5.1) | SHA-512 (FIPS 180-4 §6.4) | `1.3.6.1.5.5.7.6.48` (`id-MLDSA65-Ed25519-SHA512`) |
| 0x22 | `MlDsa44EcdsaP256Suite`     | ML-DSA-44 (FIPS 204 §4 Table 1) | ECDSA-P256 (FIPS 186-5 §6, SP 800-186 §3.2.1.3) | SHA-256 (FIPS 180-4 §6.2) | `1.3.6.1.5.5.7.6.40` (`id-MLDSA44-ECDSA-P256-SHA256`) |
| 0x23 | `MlDsa65EcdsaP256Suite`     | ML-DSA-65 (FIPS 204 §4 Table 1) | ECDSA-P256 (FIPS 186-5 §6, SP 800-186 §3.2.1.3) | SHA-512 (FIPS 180-4 §6.4) | `1.3.6.1.5.5.7.6.45` (`id-MLDSA65-ECDSA-P256-SHA512`) |

### M' construction

Composite-sigs §3.2 step 2 defines a single message representative `M'` that both sub-signers see, fixing the suite identity, the caller's `user_ctx`, and the pre-hashed message in a positional concatenation:

```
M' := Prefix || Label || len(ctx) || ctx || PH(M)
```

| Field      | Bytes | Source / value                                                                 |
|------------|-------|--------------------------------------------------------------------------------|
| `Prefix`   | 32    | ASCII `CompositeAlgorithmSignatures2025` per composite-sigs §2.2. Hex `43 6F 6D 70 6F 73 69 74 65 41 6C 67 6F 72 69 74 68 6D 53 69 67 6E 61 74 75 72 65 73 32 30 32 35`. |
| `Label`    | 30-32 | ASCII per-suite label per composite-sigs §6, no length prefix, no terminator. `COMPSIG-MLDSA44-Ed25519-SHA512`, `COMPSIG-MLDSA65-Ed25519-SHA512`, `COMPSIG-MLDSA44-ECDSA-P256-SHA256`, or `COMPSIG-MLDSA65-ECDSA-P256-SHA512`. |
| `len(ctx)` | 1     | `ctx.length` encoded as a single unsigned byte per composite-sigs §3.2 step 2. |
| `ctx`      | 0-255 | The caller-supplied `user_ctx`, verbatim, capped at 255 bytes per composite-sigs §3.2 step 1. |
| `PH(M)`    | 32 or 64 | Output of the per-suite Pre-Hash function applied to the to-be-signed message. |

`Prefix` is fixed across every suite. `Label` differentiates the four suites at the byte level, providing cross-suite domain separation without any per-call work at the suite layer.

`buildEffectiveCtx` from `src/ts/sign/ctx.ts` is NOT on the call path for these four suites. The `ctxDomain` strings exist for catalog symmetry only; user-context binding is fully specified by the M' construction. Wrapping `user_ctx` in the `{ctxDomain}|{user_ctx}` framing other leviathan suites use would produce a wire incompatible with every other Composite ML-DSA implementation.

### Component encodings

Per composite-sigs §4. PQ-first concatenation across pk, sk, and sig. No length prefixes, no separators.

| Half                | pk encoding                                                | sk encoding                                                    | sig encoding                                       |
|---------------------|------------------------------------------------------------|----------------------------------------------------------------|----------------------------------------------------|
| ML-DSA              | Raw `pkEncode` bytes per FIPS 204 §7.2; 1312 bytes for ML-DSA-44, 1952 for ML-DSA-65. | 32-byte ML-DSA seed `ξ` only per composite-sigs §4.2. The expanded sk is NOT serialised; the suite re-derives via FIPS 204 §6.1 `KeyGen_internal` per sign. | Raw `sigEncode` bytes per FIPS 204 §7.2; 2420 bytes for ML-DSA-44, 3309 for ML-DSA-65. |
| Ed25519             | 32-byte raw encoding per RFC 8032 §5.1.5.                  | 32-byte raw seed per RFC 8032 §5.1.5.                          | 64-byte raw `R || S` per RFC 8032 §5.1.6.          |
| ECDSA-P256          | 65-byte SEC 1 §2.3.4 uncompressed `0x04 || X || Y`.        | 51-byte DER-encoded `ECPrivateKey` per RFC 5915 §3: version 1, the 32-byte raw scalar in the `privateKey OCTET STRING`, the secp256r1 named-curve OID (`1.2.840.10045.3.1.7`, SP 800-186 §3.2.1.3) in `parameters [0]`, `publicKey [1]` omitted. | DER-encoded `Ecdsa-Sig-Value` per RFC 3279 §2.2.3 (`SEQUENCE { r INTEGER, s INTEGER }`), variable 8-72 bytes. |

The composite sk format trades sign-time cost (one `keygenDerand` per sign, roughly 5-15 ms depending on parameter set) for a much smaller private-key footprint and clean seed-only storage. composite-sigs §3.2 step 3 mandates this: `(_, mldsaSK) = ML-DSA.KeyGen_internal(mldsaSeed)`.

### ML-DSA native ctx

The ML-DSA sub-signer is invoked with the per-suite Label as its native `ctx` parameter, NOT with the caller-supplied `user_ctx` and NOT with the empty string. Composite-sigs §3.2 step 4:

```
mldsaSig = ML-DSA.Sign( mldsaSK, M', mldsa_ctx=Label )
tradSig  = Trad.Sign  ( tradSK,  M'                  )
```

The Label ASCII bytes flow into FIPS 204 §3.6.1's ML-DSA-internal `M' = 0x00 || |ctx| || ctx || M` line, where the outer `ctx` becomes the Label and the outer `M` becomes the composite M'. Label byte lengths cap at 32, well inside the FIPS 204 §3.6.1 255-byte ctx cap.

Pure ML-DSA inside the composite, NOT HashML-DSA. Composite-sigs §2.1 is explicit: "the ML-DSA component inside the composite is 'pure' ML-DSA". HashML-DSA would corrupt the wire format with the FIPS 204 §3.6.4 domain-sep byte `0x01` and the pre-hash OID DER bytes.

### Traditional component input

The traditional sub-signer signs `M'` directly per composite-sigs §3.2 step 4. No additional wrapping at the composite layer; whatever hashing the traditional primitive does happens inside its own specification.

- **Ed25519 pure** (RFC 8032 §5.1.6) runs its standard SHA-512 chain over `R || A || M'` with `M'` as the message. The composite-layer PH (SHA-512) and the Ed25519-internal SHA-512 are two distinct hash invocations: the composite layer produces `PH(M) = SHA-512(M)` and inserts it into `M'`; Ed25519 then hashes `R || A || M'` per its own RFC 8032 procedure.
- **ECDSA-P256** (FIPS 186-5 §6.4 with `ecdsa-with-SHA256`) runs SHA-256 over `M'` to produce the 32-byte message hash, then signs that hash. For `MlDsa65EcdsaP256Suite` the composite PH is SHA-512, so `M'` contains 64 bytes of `PH(M) = SHA-512(M)`, but the ECDSA-internal hash is still SHA-256(M'). Composite-sigs §6 names the ECDSA half `ecdsa-with-SHA256` for BOTH `0x22` and `0x23`; composite-sigs §10.1 calls this out as a deliberate deployment-fit choice: "`ecdsa-with-SHA256` with secp256r1 is far more common than, for example, `ecdsa-with-SHA512` with secp256r1."

### Wire format

The combined signature lives inside the same v3 attached envelope every other suite uses. The envelope's `suite_byte` distinguishes a classical+PQ hybrid from any other suite, and the rest of the wire layout follows the [Attached envelope](#attached-envelope) shape with `sigMaxSize` taken from the hybrid suite. For the Ed25519 hybrids `sig` is fixed-length; for the ECDSA hybrids the ML-DSA half is fixed and the ECDSA-half DER length varies inside `[8, 72]` bytes, so the trailing sig fills the remaining envelope bytes after the `payload_len`-bounded payload.

For detached signatures, `Sign.signDetached` returns the spec-compliant `sig_combined` bytes:

- Ed25519 hybrids: `sig_mldsa || sig_ed25519` (fixed length).
- ECDSA hybrids: `sig_mldsa || sig_ecdsa_der` (variable length, ML-DSA-fixed prefix plus the DER `Ecdsa-Sig-Value`).

No envelope, no length prefix, no leviathan-specific framing. The detached form is the interop surface for systems that already understand the composite-sigs draft.

### Sign / verify pseudocode

```text
suite.signPrehashed(sk, digest, ctx):
    require digest.length == prehashSize
    require sk.length     == skSize
    require ctx.length    <= 255                   // composite-sigs §3.2 step 1
    seed_mldsa   = sk[0 .. 32]
    sk_trad      = sk[32 .. ]                      // 32 raw Ed25519 OR 51 DER ECPrivateKey
    M_prime      = COMPOSITE_PREFIX || Label || len(ctx) || ctx || digest
    expanded_sk  = ML-DSA.KeyGen_internal(seed_mldsa)
    sig_mldsa    = ML-DSA.Sign(expanded_sk, M_prime, mldsa_ctx=Label)
    sig_trad     = Trad.Sign(sk_trad, M_prime)     // Ed25519: M', ECDSA: SHA-256(M')
    return sig_mldsa || sig_trad                   // PQ-first
```

```text
suite.verifyPrehashed(pk, digest, sig, ctx):
    if pk.length     != pkSize:      return false  // wire-shape, soft-fail
    if sig.length    out of bounds:  return false
    require digest.length == prehashSize           // contract violation, throw
    require ctx.length    <= 255
    pk_mldsa     = pk[0 .. mldsaParams.pkBytes]
    pk_trad      = pk[mldsaParams.pkBytes .. ]
    sig_mldsa    = sig[0 .. mldsaParams.sigBytes]
    sig_trad     = sig[mldsaParams.sigBytes .. ]
    M_prime      = COMPOSITE_PREFIX || Label || len(ctx) || ctx || digest
    mldsa_ok     = ML-DSA.Verify(pk_mldsa, M_prime, sig_mldsa, mldsa_ctx=Label)  // GATE: always runs
    trad_ok      = Trad.Verify  (pk_trad,  M_prime, sig_trad)                    // GATE: always runs
    return mldsa_ok AND trad_ok                                                  // AND-reduce after both
```

Both sub-verifies always run; the trailing AND is a boolean reduction over precomputed values, not a short-circuit. See "Constant-time discipline" below.

### Hedged-vs-deterministic posture

Composite-sigs is silent on hedged-vs-deterministic ECDSA. The leviathan defaults match the rest of the catalog:

- **ML-DSA**: hedged-by-default per FIPS 204 §3.7 recommendation. `rnd = randomBytes(32)` mixed into the rejection-sampling state per sign.
- **ECDSA-P256**: hedged-by-default per `draft-irtf-cfrg-det-sigs-with-noise-05` §4. `rnd = randomBytes(32)` mixed into the K derivation per sign.
- **Ed25519**: deterministic by construction per RFC 8032 §5.1.6 (`r = SHA-512(prefix || M)`). No hedging knob exists at the primitive level.

The composite signature is therefore non-deterministic for both ECDSA suites and the ML-DSA half of the Ed25519 suites. Two `sign` calls on the same `(sk, msg, ctx)` produce different composite signatures; both verify under the same composite pk.

### Constant-time discipline (divergence from spec)

Composite-sigs §3.3 explicitly permits early-fail on the ML-DSA verify: "no private keys are involved in a signature verification, there are no timing attacks to consider, so this is ok." Leviathan declines this permission and runs both sub-verifies on every call, matching the [PQ-only hybrid](#pq-only-hybrid-composite-encoding) posture.

The reference implementation declares `mldsaOk` and `tradOk` without initial values so neither variable is readable until both sub-verifies have completed; the trailing `mldsa_ok AND trad_ok` is a boolean AND on values that have already been computed. Total verify work is the sum of the two sub-verifies regardless of which half (if either) fails. A timing observer cannot distinguish "ML-DSA failed" from "ECDSA failed" from "both failed".

This is strictly stronger than the draft and does not break interop: the wire format is identical, and the accept/reject decision is identical on every well-formed input. The only observable difference is timing on the invalid-ML-DSA / valid-trad case; the draft permits leaking which half failed, leviathan declines to.

For the ECDSA hybrids, DER decode failure on the trad-half also folds into `trad_ok = false` rather than propagating an exception, so a malformed trad-half does not short-circuit the ML-DSA verify either.

ECDSA-half low-S normalisation: composite-sigs is silent on low-S enforcement; the Appendix E reference signatures include high-S cases that leviathan's strict-S `EcdsaP256.verify` would reject standalone. The composite verify normalises high-S signatures to their equivalent low-S form via `s ← (n - s)` before calling `EcdsaP256.verify` (FIPS 186-5 §6.5 accepts both s and n - s under the same pk), preserving interop with the spec's reference vectors without weakening the standalone suite's strict-S posture.

### Streamable surface

All four hybrids implement `StreamableSignatureSuite` and plug into `SignStream` / `VerifyStream`. Composite-sigs §10.5 explicitly permits external pre-hashing, and the suite's `prehashAlgorithm` is precisely the composite Pre-Hash function: a caller-supplied `digest = PH(M)` slots straight into the M' construction as the trailing `PH(M)` field. The streaming path computes `PH(M)` incrementally via `createRunningHash` and feeds the digest to `signPrehashed` on finalize, the same shape as the PQ-only hybrid streaming path.

### Domain separation

Each suite's `Label` ASCII bytes are distinct, so the M' construction binds each suite uniquely without any cross-suite collision:

- A signature produced under `MlDsa44Ed25519Suite` (`0x20`) does NOT verify as the ML-DSA half of `MlDsa65Ed25519Suite` (`0x21`) because the Label and ML-DSA parameter set both differ.
- A signature produced under `MlDsa44EcdsaP256Suite` (`0x22`) does NOT verify as `MlDsa44Ed25519Suite` (`0x20`) because the M' Label byte sequence differs at byte 32 of the construction.
- A signature produced under any composite ML-DSA suite does NOT verify under standalone `MlDsa44Suite` / `MlDsa65Suite` / `EcdsaP256Suite` because the standalone suites' M' constructions do not include the composite Prefix and Label.

No per-half ctxDomain suffix is needed. The composite Prefix and per-suite Label provide all the separation the construction requires.

---

## Wire format

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

## Interface reference

### `SignatureSuite`

| Field         | Type                | Description |
|---------------|---------------------|-------------|
| `formatEnum`  | `number`            | Wire format byte. Bits 0-3 select within category, bits 4-5 select category (`0x0X` pure, `0x1X` prehash, `0x2X` classical+PQ hybrid, `0x3X` PQ-only hybrid), bits 6-7 reserved. |
| `formatName`  | `string`            | Human label, for example `'mldsa65'` or `'mldsa65-prehash'`. |
| `ctxDomain`   | `string`            | Built-in domain separator concatenated with the user ctx before reaching the underlying primitive. Capped at 32 bytes (UTF-8) at factory construction. |
| `pkSize`      | `number`            | Public key size in bytes. |
| `skSize`      | `number`            | Secret key size in bytes. |
| `sigMaxSize`  | `number`            | Upper-bound signature size in bytes. For fixed-length suites equals the actual size; for variable-length suites (composite ECDSA) is the catalog-reserved upper bound per the underlying spec. |
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
- `verify` returns boolean for every signature outcome: wrong sig, malformed hint encoding, wrong-length pk or sig per FIPS 204 §3.6.2. Contract violations such as `user_ctx.length > USER_CTX_MAX` (255 per FIPS 204 §3.6.1) throw `SigningError`.
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

- `ctxDomain ≤ 32 bytes` after UTF-8 encoding. Validated at factory-construction time. Passing a longer string throws a plain `Error` because that is a developer-time mistake, not a caller mistake.
- `user_ctx ≤ USER_CTX_MAX (255 bytes)` per call. Validated each time. Throws `SigningError('sig-ctx-too-long')`. Matches the native ctx cap from FIPS 204 §3.6.1.
- Combined `effective_ctx ≤ 255 bytes` per call. `buildEffectiveCtx` re-checks the framed output because that buffer is what flows into FIPS 204's ctx parameter, and the FIPS 204 §3.6.1 cap is `255` end to end. The check fires after the absolute `user_ctx` cap, so any caller exceeding the absolute cap always trips the first throw. The combined cap matters in practice for suites whose `ctxDomain` is long enough that a max-length `user_ctx` overflows the 2-byte-prefix layout. The effective per-call user_ctx ceiling for those suites is `253 - len(ctxDomain)`, ranging 221-234 bytes across the shipped catalog. Both throws share the `sig-ctx-too-long` discriminator.

The wire `ctx_len` field is `u8`, so the wire layer matches the same 0-255 range. Suites that bind user_ctx into the underlying primitive through a different framing (e.g., a composite signer that places `user_ctx` directly into an `M'` construction per draft-ietf-lamps-pq-composite-sigs §3.2 step 1) bypass `buildEffectiveCtx` and enforce the absolute 255-byte cap inline.

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
| `sig-ctx-too-long`      | suite             | `user_ctx` exceeds USER_CTX_MAX (255 bytes per FIPS 204 §3.6.1), or the combined `effective_ctx` from `buildEffectiveCtx` exceeds the same cap. |
| `sig-ctx-unsupported`   | suite             | Non-empty `user_ctx` passed to a suite with no native context parameter (`Ed25519Suite`, pure-mode 0x01). Pure RFC 8032 §5.1.6 Ed25519 has no ctx; context-bound signing must use `Ed25519PreHashSuite` (0x11) via dom2(F=1, ctx). Future pure-only suites (e.g. Ed448) reuse the same discriminator. |
| `sig-malformed-input`   | suite             | Primitive validation failure, for example a wrong-length digest in `signPrehashed` or `verifyPrehashed` (both throw symmetrically). |
| `sig-blob-too-short`    | envelope          | Wire-shape rejection. Fires on a blob shorter than the 6-byte envelope header, on `ctx_len` pushing past the blob end, on `payload_len` pushing the payload past the blob end, or on a trailing sig larger than `suite.sigMaxSize`. The thrown `SigningError`'s `.message` names the specific overflow. |
| `sig-suite-unknown`     | envelope          | Wire `suite_byte` is not in the catalog. Reserved; callers pass the suite explicitly today, so this discriminator does not fire. |
| `sig-suite-mismatch`    | envelope, stream  | Wire `suite_byte` does not equal the caller's `suite.formatEnum`. |
| `sig-ctx-overflow`      | envelope          | Catalog discriminator retained for compatibility; the v3 envelope folds the ctx-past-blob case into `sig-blob-too-short`. Reserved for future routing APIs. |
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
// ok === true; for fixed-length suites sig is exactly MlDsa65Suite.sigMaxSize bytes
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

const signer = new SignStream(MlDsa65PreHashSuite, sk, ctx)
signer.update(chunk1)
signer.update(chunk2)
const sig = signer.finalize()
// payload length is known once finalize() returns. The v3 envelope's
// payload_len header is built at the end via buildPreamble(N).
const payloadLen = chunk1.length + chunk2.length
const preamble = signer.buildPreamble(payloadLen)
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

`update` accepts arbitrarily-sized chunks; the verify-stream parses byte-by-byte through the 6-byte v3 header (suite + ctx_len + ctx + payload_len), then consumes exactly `payload_len` bytes of payload, then buffers the trailing bytes as the sig until `finalize`. A receiver that doesn't yet know which suite produced the wire bytes can call `Sign.peek` (next example) before constructing `VerifyStream`.

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

## Memory hygiene

Three layers each hold a copy of secret-adjacent state. The library wipes its copies on well-defined boundaries; caller-owned buffers are never touched.

### SignStream

`new SignStream(suite, sk, ctx)` copies `ctx` into a lib-owned `Uint8Array`. `sk` is held by reference and never wiped. The running prehash is disposed in both `finalize()` and `dispose()`.

The ctx copy survives `finalize()` deliberately. `buildPreamble(payloadLength)` is available at any point in the stream lifecycle, and the canonical assembly pattern calls `finalize()`, then `buildPreamble()`, then concatenates the blob. Wiping ctx earlier would zero the preamble's ctx field. `dispose()` wipes the ctx copy, so call it once the blob is assembled.

### VerifyStream

`update(chunk)` copies every payload byte into an internally-owned chunk so a caller-side mutation cannot retroactively change the buffered payload. `pk` and the expected `ctx` are held by reference and never wiped.

`finalize()` wipes `payloadChunks`, `sigBuf`, and `headerBuf` on both the success path and every failure path. The returned payload is a fresh `concat(...)` allocation, so wiping the internal chunks does not corrupt the result. `dispose()` performs the same wipe and is idempotent.

### Suite methods

Each suite call instantiates a fresh primitive class, runs the operation inside a `try`, and calls `dispose()` in `finally`. The primitive's `dispose()` invokes the WASM module's `wipeBuffers()`, so key material does not persist in linear memory between calls.

Lib-allocated temporaries get the same treatment:

- `effective_ctx` (the `{ctxDomain}|{user_ctx}` build) is wiped in `finally` after the primitive returns.
- One-shot prehash digests inside non-streaming `sign` and `verify` entry points are wiped in `finally`.
- The hedged-entropy `rnd` buffer inside the ECDSA-P256 sign path is wiped in `finally`.

Caller-owned buffers are never wiped: `sk`, `pk`, `msg`, the `digest` passed to `signPrehashed` and `verifyPrehashed`, `sig`, and the user `ctx`. Hybrid verify paths take subarray views over caller-owned `sig` and `pk`; those views inherit the same rule.

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
| 0x20 | `MlDsa44Ed25519Suite`       | hybrid  | SHA-512               | `mldsa44-ed25519-envelope-v3`      | shipped  |
| 0x21 | `MlDsa65Ed25519Suite`       | hybrid  | SHA-512               | `mldsa65-ed25519-envelope-v3`      | shipped  |
| 0x22 | `MlDsa44EcdsaP256Suite`     | hybrid  | SHA-256               | `mldsa44-ecdsa-p256-envelope-v3`   | shipped  |
| 0x23 | `MlDsa65EcdsaP256Suite`     | hybrid  | SHA-512               | `mldsa65-ecdsa-p256-envelope-v3`   | shipped  |
| 0x30 | `MlDsa44SlhDsa128fSuite`    | hybrid  | SHAKE-128             | `mldsa44-slhdsa128f-envelope-v3`   | shipped  |
| 0x31 | `MlDsa65SlhDsa192fSuite`    | hybrid  | SHAKE-256             | `mldsa65-slhdsa192f-envelope-v3`   | shipped  |
| 0x32 | `MlDsa87SlhDsa256fSuite`    | hybrid  | SHAKE-256             | `mldsa87-slhdsa256f-envelope-v3`   | shipped  |

22 of 64 slots used. Reserved capacity covers Ed448, ECDSA-P384, brainpool curves, FROST suites, ML-DSA-87 classical hybrids, and threshold variants.

The classical+PQ hybrid bytes (`0x20-0x23`) follow the `draft-ietf-lamps-pq-composite-sigs` Composite ML-DSA encoding; see the [Classical+PQ hybrid composite encoding](#classicalpq-hybrid-composite-encoding) section above for the full wire layout, M' construction, hedged posture, and constant-time discipline. The PQ-only hybrid bytes (`0x30-0x32`) are leviathan-flavored; see the [PQ-only hybrid composite encoding](#pq-only-hybrid-composite-encoding) section above for the full wire layout, prehash alignment, and constant-time discipline.

---

## Custom suites

`SignatureSuite` is a TypeScript interface, not a sealed class. A consumer can satisfy the interface and pass a custom suite to `Sign`, `SignStream`, and `VerifyStream`. The catalog format bytes are reserved by the library, so a custom suite must pick a `formatEnum` outside the allocated range. No specific custom-suite range is reserved today; if you need one, raise an issue.

Custom suites do not get the factory helpers the in-tree suites use. You are responsible for the per-call WASM lifecycle, the `ctxDomain` cap, the `effective_ctx` construction, and the per-method wipe discipline. Read `src/ts/sign/suites/mldsa.ts` before writing one; the mldsa-suites factory captures every invariant the in-tree suites satisfy.

---

## Threat model

### Pure versus prehash

Pure-mode suites bind the full message bytes inside FIPS 204's M' construction (`M' = 0x00 ‖ |ctx| ‖ ctx ‖ M`). Prehash-mode suites compose with FIPS 204 §5.4 HashML-DSA, which substitutes `M' = 0x01 ‖ |ctx| ‖ ctx ‖ OID(ph) ‖ Hash(M, ph)`. The domain-separator byte differs (`0x00` vs `0x01`), so a signature produced in one mode never verifies in the other on the same key.

Pure mode offers the larger collision-resistance margin because the signature binds the message bytes themselves. Prehash mode is necessary when the application cannot buffer `M`; the streaming layer in this library uses it for that reason.

### Classical+PQ hybrid (`0x2X`)

Classical+PQ hybrids defend against the case where the PQ assumption (M-LWE for ML-DSA) is broken before a CRQC arrives. The classical half (Ed25519 or ECDSA-P256) keeps signatures unforgeable in that world. These hybrids do not defend against a CRQC adversary; the classical half falls to Shor's algorithm. Ship them when you need ecosystem interop or PKI migration, not when the threat model assumes a future CRQC. See [Classical+PQ hybrid composite encoding](#classicalpq-hybrid-composite-encoding) above for the wire format and [SECURITY.md](../SECURITY.md) for the threat model.

### PQ-only hybrid (`0x3X`)

PQ-only hybrids defend against the case where one PQ family is broken while the other holds. ML-DSA pairs with SLH-DSA, which rests on a different cryptanalytic foundation (hash-based, no lattice assumption). Neither half falls to Shor's algorithm; Grover's quadratic speedup only halves SLH-DSA's bit security, well above its design margin. Pick PQ-only hybrids when you need "this signature must verify in 2050."

See the [PQ-only hybrid composite encoding](#pq-only-hybrid-composite-encoding) section above for the wire format and constant-time discipline, and [SECURITY.md](../SECURITY.md#pq-only-hybrid-signature-threat-model) for the full threat model including what these hybrids do NOT defend against.

The library carries both hybrid families because consumer threat models differ. Classical hybrids serve adoption and interop; PQ-only hybrids serve long-horizon assurance.

---

## Cross-References

| Document | Description |
|----------|-------------|
| [README](./README.md) | Documentation index |
| [architecture](./architecture.md) | Repository structure, build and CI, WASM modules, public API, test suite, and security posture |
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
