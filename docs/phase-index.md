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
| 6     | BLAKE3-derived signature work                               | queued     |
| 7     | Merkle log + signed tree head (RELEASE)                     | queued     |

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

## Phase 6 unblock note

Phase 6 was blocked on the SHA-256 streaming-prehash slot in
`src/ts/sign/hasher.ts`. Phase 5 resolves that slot via the
`sha256Buffered` shim (buffered over the one-shot `SHA256`
class, byte-identical at `finalize()` to a one-shot SHA-256
over the concatenated chunks). Phase 6 work that needs a
streaming SHA-256 prehash inherits the shim and the matching
`createRunningHash('sha-256')` dispatch without further
substrate work.

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
