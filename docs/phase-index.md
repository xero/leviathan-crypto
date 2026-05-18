<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### v3 Signature Roadmap, Phase Index

Per-phase status of the v3 signature roadmap. Each row is the
release-state of the WASM substrate, TS class wrapper, suite
factory, test corpus, and documentation surface for that phase.

| Phase | Scope                                                       | Status     |
|-------|-------------------------------------------------------------|------------|
| 1     | `Sign` envelope + `SignStream` / `VerifyStream` + ML-DSA suites (pure + prehash) | shipped    |
| 2     | SLH-DSA suites (pure + prehash) + PQ-only hybrid composites | shipped    |
| 3     | BLAKE3 substrate (tree mode + XOF + Fortuna `HashFn`)       | shipped    |
| 4     | Curve25519 family (Ed25519 pure + Ed25519ph, X25519 DH)     | shipped    |
| 5     | ECDSA over NIST P-256 (FIPS 186-5 §6 + RFC 6979 + SHA-256)  | shipped    |
| 6     | Classical+PQ composite hybrid suites (ML-DSA + Ed25519 / ECDSA-P256) | shipped    |
| 7     | BLAKE3-derived signature work                               | queued     |
| 8     | Merkle log + signed tree head (RELEASE)                     | queued     |

---

## Phase 5 shipped artefacts

The current release covers:

- `p256.wasm` substrate, the twelfth WASM binary in the library.
  Field arithmetic over GF(p256) with HMV §2.4.1 Algorithm 2.27
  Solinas reduction, short-Weierstrass projective points via
  Renes-Costello-Batina 2016 complete addition (Algorithm 4 add,
  Algorithm 6 double, specialised for `a = -3`), constant-time
  fixed-base and variable-base scalar multiplication, embedded
  SHA-256 plus HMAC-SHA-256 for RFC 6979 §3.2 K derivation, and
  the FIPS 186-5 §6.4 / §6.4.4 ECDSA sign / verify entry points
  with low-S enforcement.
- `EcdsaP256` class at `leviathan-crypto/ecdsa`. Public API
  surfaces `keygen` / `keygenDerand(seed)`, hedged-or-deterministic
  `sign(sk, pk, msgHash, rnd)`, suite-only `_signInternalPk`,
  strict `verify(pk, msgHash, sig)`, and `dispose`. See
  [ecdsa-p256.md](./ecdsa-p256.md) for the full reference.
- `EcdsaP256Suite` at format byte `0x02`. Single mode with
  SHA-256 prehash baked in (ECDSA has no native pure mode).
  Hedged-by-default per
  `draft-irtf-cfrg-det-sigs-with-noise-05`. Rejects non-empty
  `user_ctx` because FIPS 186-5 §6.4 has no native ctx
  parameter; context-bound ECDSA-P256 lives in the classical+PQ
  hybrid suites at `0x22` / `0x23` (reserved).
- `ecdsaSignatureToDer` / `ecdsaSignatureFromDer` at
  `leviathan-crypto/ecdsa`. Strict-DER codec per RFC 3279
  §2.2.3, ECDSA Signature Algorithm, for X.509 / JWS / TLS
  interop. The WASM ABI and the suite wire format both use raw
  r || s; the DER helpers are a side utility.
- Full test corpus: 9 substrate unit tests, 2 ECDSA class
  tests, 4 sign-layer tests, plus the Rust verifier coverage.
  RFC 6979 §A.2.5 (deterministic-K gate), NIST ACVP
  ECDSA-FIPS186-5 keyGen / sigGen / sigVer filtered to
  P-256 + SHA-256, and C2SP Wycheproof
  `ecdsa_secp256r1_sha256_p1363` records all run through both
  the WASM stack and the independent
  RustCrypto-`p256` / `ecdsa`-based oracle. See
  [vector_audit.md](./vector_audit.md) for the verifier story.

---

## Phase 6 shipped artefacts

The current release covers the four IETF `draft-ietf-lamps-pq-composite-sigs`
composite ML-DSA suites at format bytes `0x20`-`0x23`:

- `MlDsa44Ed25519Suite` (`0x20`, `id-MLDSA44-Ed25519-SHA512`, OID
  `1.3.6.1.5.5.7.6.39`).
- `MlDsa65Ed25519Suite` (`0x21`, `id-MLDSA65-Ed25519-SHA512`, OID
  `1.3.6.1.5.5.7.6.48`).
- `MlDsa44EcdsaP256Suite` (`0x22`, `id-MLDSA44-ECDSA-P256-SHA256`,
  OID `1.3.6.1.5.5.7.6.40`).
- `MlDsa65EcdsaP256Suite` (`0x23`, `id-MLDSA65-ECDSA-P256-SHA512`,
  OID `1.3.6.1.5.5.7.6.45`).

All four implement `StreamableSignatureSuite`, plug into `SignStream` /
`VerifyStream`, and bind the caller-supplied `user_ctx` through the
composite-sigs §3.2 `M' = Prefix || Label || len(ctx) || ctx || PH(M)`
construction (no `buildEffectiveCtx`). The ECDSA half hashes
`SHA-256(M')` for both ECDSA suites per composite-sigs §6
`ecdsa-with-SHA256`; the composite-layer PH varies by suite (SHA-256
at `0x22`, SHA-512 elsewhere). The ML-DSA half always uses pure
ML-DSA (FIPS 204 §5.2 Algorithm 2, not HashML-DSA) with the per-suite
Label as its native `mldsa_ctx`. Signature serialisation is PQ-first
concatenation per composite-sigs §4.3: `sig = sig_mldsa || sig_trad`,
with `sig_trad` raw 64-byte `R || S` for Ed25519 and DER-encoded
`Ecdsa-Sig-Value` (RFC 3279 §2.2.3) for ECDSA-P256.

Composite private keys are 32-byte ML-DSA seed concatenated with the
traditional half per composite-sigs §4.2 (32-byte raw Ed25519 seed
or 51-byte DER `ECPrivateKey` per RFC 5915 §3). The expanded ML-DSA
signing key is re-derived per sign via `keygenDerand` and never
serialised.

Foundation changes that landed alongside the suites:

- v3 envelope wire format adds `payload_len: u32 BE` at the head of
  the payload. Variable-length signatures (composite ECDSA at
  `0x22` / `0x23`) require length-aware framing; the field is
  uniform across the catalog. Sig fills the remaining tail.
- `SignatureSuite.sigSize` renamed to `sigMaxSize`; semantics are
  now an upper bound. Fixed-length suites' upper bound equals the
  actual size; variable-length suites set the upper bound per
  composite-sigs Appendix A Table 4.
- `USER_CTX_MAX` raised to 255 library-wide (FIPS 204 §3.6.1
  native ctx cap, composite-sigs §3.2 step 1 cap).
  `buildEffectiveCtx`-using suites add a second check on the
  combined output length so the effective per-call ceiling is
  `253 - len(ctxDomain)`.
- ECDSA-P256 surface gains `pointDecompress` (free function),
  `EcdsaP256.keygenUncompressed`, and `encodeEcPrivateKey` /
  `decodeEcPrivateKey` for the SEC 1 §2.3.4 uncompressed pk and
  RFC 5915 §3 DER private-key encodings the composite suites need.

---

## Phase 6 unblock note (historical)

The Phase 6 work was originally blocked on the SHA-256 streaming-prehash
slot in `src/ts/sign/hasher.ts`. Phase 5 resolved that slot via the
`sha256Buffered` shim (buffered over the one-shot `SHA256` class,
byte-identical at `finalize()` to a one-shot SHA-256 over the
concatenated chunks). Phase 6 inherited the shim and the matching
`createRunningHash('sha-256')` dispatch without further substrate work.

---

## Cross-references

| Document | Description |
|----------|-------------|
| [signaturesuite](./signaturesuite.md) | `SignatureSuite`, `Sign`, `SignStream`, `VerifyStream`, plus the shipped suite catalog |
| [ecdsa-p256](./ecdsa-p256.md) | ECDSA-P256 public API reference (Phase 5) |
| [ed25519](./ed25519.md) | Ed25519 public API reference (Phase 4) |
| [mldsa](./mldsa.md) | ML-DSA public API reference (Phase 1) |
| [slhdsa](./slhdsa.md) | SLH-DSA public API reference (Phase 2) |
| [blake3](./blake3.md) | BLAKE3 public API reference (Phase 3) |
