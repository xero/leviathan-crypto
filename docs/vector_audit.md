<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### Test Vector Audit

How leviathan-crypto's test vectors are sourced, classified, and independently verified. The verification chain mixes pinned external authorities, an immutability-checking shasum gate in CI, and an independent Rust verifier that re-derives every self-generated wire format from primitives that share zero code with leviathan-crypto.

> ### Table of Contents
> - [Tier Classification](#tier-classification)
> - [What the Verifier Proves](#what-the-verifier-proves)
> - [What the Verifier Does NOT Prove](#what-the-verifier-does-not-prove)
> - [Provenance of Pinned Vectors](#provenance-of-pinned-vectors)
> - [CI Integration](#ci-integration)
> - [How to Add a New Cipher](#how-to-add-a-new-cipher)
> - [Cross-References](#cross-references)

---

## Tier Classification

Test vectors fall into four tiers based on their authority and how their correctness can be checked. Verification strategy varies by tier.

**Tier 1: External authority.** Vectors come from NIST CAVP, NIST ACVP, RFC test appendices, or NESSIE. The vector files in `test/vectors/` are byte-for-byte copies of the upstream files, with provenance recorded below. These vectors define correctness for their primitives, so re-deriving the expected outputs in a parallel implementation does not establish a new fact about the primitive itself; the alternative implementation is tested against the same vectors. The verifier still re-derives several Tier 1 primitives (AES across modes, POLYVAL, ML-KEM, ML-DSA) against RustCrypto as a transcription audit, catching copy-paste errors when ACVP / CAVP / RFC records were ported into the repo. The first-line audit discipline remains provenance: the upstream URL is recorded, the file checksum is pinned in `test/vectors/SHA256SUMS`, and any change requires a fresh download from the authoritative source.

**Tier 2: Self-generated over standard primitives.** Vectors encode wire formats designed by leviathan-crypto, but the underlying primitives are well-defined and have multiple independent implementations. The seal and sealstream KAT vectors live here. Re-deriving them in a different language with a different crypto stack is meaningful evidence the wire format claim holds. This is the target of the Rust verifier.

**Tier 3: Self-generated over custom primitives.** The construction is unique to leviathan-crypto and has no external reference implementation. The SPQR ratchet KATs and Fortuna PRNG KATs live here. The audit discipline is internal consistency: round-trip tests, never-reuse-nonce invariants, forward-secrecy property tests. Cross-language verification has no external authority to verify against.

**Tier 4: Hybrid.** Vectors that wrap a Tier 1 primitive in a Tier 2 construction. Kyber-suite seal blobs are an example. The KEM ciphertext piece is Tier 1 (NIST ACVP defines correctness). The seal-format wrapper is Tier 2 (we designed it). The verifier independently covers the ML-KEM primitive against ACVP and covers symmetric Tier 2 wrappers, but it does not yet exercise KEM-wrapped seal blobs end to end. The two pieces are verified separately; their composition is not yet a single verifier target.

---

## What the Verifier Proves

The Rust verifier at `scripts/verify-vectors/` re-derives every byte of every Tier 2 vector from primitives that share zero code with leviathan-crypto's WASM implementation. Specifically:

**XChaCha20 v3 seal and sealstream.** Verified against:
- HKDF-SHA-256 from RustCrypto's `hkdf` + `sha2` crates.
- HChaCha20 hand-rolled from RFC 8439 §2.3 in pure Rust with no external dependency.
- ChaCha20-Poly1305 from RustCrypto's `chacha20poly1305` crate.

The verifier independently computes the 32-byte key commitment from HKDF bytes 32..64 and asserts it matches the pinned preamble, then encrypts each chunk with the derived subkey and compares the wire bytes. Multi-chunk path verifies per-chunk counter increment, TAG_DATA versus TAG_FINAL flag handling, and framed-mode `u32be` length prefixes.

**Serpent v3 seal and sealstream.** Verified against:
- HKDF-SHA-256 from RustCrypto's `hkdf` + `sha2` crates (96-byte output).
- HMAC-SHA-256 from RustCrypto's `hmac` crate, used both for per-chunk IV derivation and for chunk authentication.
- Serpent block cipher from RustCrypto's `serpent = "0.6"` crate, separately confirmed byte-correct against NESSIE Set 1 vector#0 across all three key sizes (128/192/256).
- CBC chaining and PKCS#7 padding hand-rolled from spec.

Both leviathan-crypto v3 and RustCrypto's `serpent` crate use NIST natural byte order at their public APIs. The verifier feeds keys, IVs, and plaintext blocks through unchanged; no byte-reversal dance applies at the block-cipher boundary. v2 used the AES-submission floppy byte order at its public API and required a reversal at this boundary; v3 removes that asymmetry.

**AES-GCM-SIV v3 seal and sealstream.** Verified against:
- HKDF-SHA-256 from RustCrypto's `hkdf` + `sha2` crates.
- AES-256-GCM-SIV from RustCrypto's `aes-gcm-siv` crate, already pinned for the Tier 1 RFC 8452 target and reused here as the per-chunk AEAD for the Tier 2 seal wrapper.

The structural shape mirrors XChaCha20 v3 byte for byte: same HKDF info-binding pattern with the 20-byte header concatenated to the info string, same 52-byte preamble (20-byte header plus 32-byte commitment), same 12-byte counter-nonce per chunk, same framed-mode `u32be` length prefix on the wire. The only difference is the AEAD primitive and the absence of an HChaCha20-equivalent subkey step; AES-GCM-SIV consumes the 32-byte HKDF output directly. The verifier independently recomputes the commitment from HKDF bytes 32..64, asserts byte-equality with the pinned preamble, encrypts each chunk with the derived key and counter nonce, and compares wire bytes for both unframed and framed shapes.

**AES symmetric primitives.** Verified against:
- AES block cipher (FIPS 197) from RustCrypto's `aes` crate, exercising all three key sizes (128, 192, 256) against the FIPS 197 known-answer vectors.
- AES-CBC (NIST SP 800-38A) from RustCrypto's `cbc` crate.
- AES-CTR (NIST SP 800-38A) from RustCrypto's `ctr` crate.
- AES-GCM (NIST SP 800-38D + January 2004 submission CAVP `.rsp` vectors) from RustCrypto's `aes-gcm` crate.
- AES-GCM-SIV (RFC 8452) from RustCrypto's `aes-gcm-siv` crate.

Each AES target reads its respective KAT file and asserts byte-for-byte agreement with RustCrypto's output for every record. The role here is transcription audit: catching any error introduced when the original NIST or RFC records were ported into the repo's `.ts` vector format.

**POLYVAL primitive.** Verified against RustCrypto's `polyval` crate, which implements the universal hash directly per RFC 8452 §3. POLYVAL stands as its own target separate from AES-GCM-SIV because the test corpus includes the §7 / Appendix A KATs that exercise POLYVAL's reflected-GHASH structure independent of the AEAD wrapper.

**ML-KEM primitive (FIPS 203).** Verified against RustCrypto's `ml-kem` crate. The verifier reads the NIST ACVP `keyGen` and `encap+decap` records (`kyber_keygen.ts`, `kyber_encapdecap.ts`) and reproduces every ACVP-published expected output:

- §6.1 KeyGen_internal: `KeyGen::from_seed(d ‖ z)` returns dk; the matching ek encoding compares to `pk` and the dk encoding to `sk`.
- §6.2 Encaps_internal: `EncapsulationKey::encapsulate_deterministic(m)` reproduces the ACVP `(c, k)` pair given the published 32-byte message m.
- §6.3 Decaps_internal: `Decapsulate::decapsulate_slice(c)` reproduces the expected k. For modified-ciphertext records, the FO transform's implicit-rejection branch returns a pseudorandom secret matching the published k.
- §7.2 / §7.3: `EncapsulationKey::new` and the deprecated `from_expanded` natively perform the encap-key and decap-key validity round-trip checks, with `Err` returned on failure.

**ML-DSA primitive (FIPS 204).** Verified against RustCrypto's `ml-dsa` crate (rc.9). The verifier reads the NIST ACVP `keyGen`, `sigGen`, and `sigVer` records (`mldsa_keygen.ts`, `mldsa_siggen.ts`, `mldsa_sigver.ts`, ACVP vsId=42) and reproduces:

- KeyGen: `KeyGen::from_seed(ξ)` returns a `SigningKey<P>`; the pk and expanded sk encodings (FIPS 204 Algorithms 22 + 24) compare to ACVP `pk` and `sk`.
- SigGen: the verifier rebuilds M' per (signatureInterface, preHash, externalMu) per FIPS 204 §6.2 / §5.4 and calls `sign_internal(&[M'], &rnd)` (or `sign_mu_*` for externalMu). Deterministic mode passes the all-zero 32-byte vector as rnd; hedged signing checks against ACVP's published per-record rnd.
- SigVer: `VerifyingKey::decode(pk_bytes)` plus `Signature::decode(...)`, then `verify_internal(&M', &sig)` (or `verify_mu(mu, &sig)`). The boolean result compares to ACVP `testPassed`. The pinned rc.9 sits on the patched side of GHSA-5x2r-hc65-25f9 (sigVer previously accepted hint vectors with non-strictly-increasing indices), so hint-malleability rejection records validate cleanly.

**Ed25519 and X25519 (RFC 8032 / RFC 7748).** Verified against:

- ed25519-dalek 2.2.0 (dalek-cryptography organisation).
- x25519-dalek 2.0.1 (dalek-cryptography organisation).
- curve25519-dalek 4.1.3 (dalek-cryptography organisation), pinned
  explicitly so the curve arithmetic crate is part of the audit
  surface rather than left to whatever happens to satisfy the open
  `^4` bound at build time.

dalek-cryptography is the first verifier lineage outside the RustCrypto
organisation and outside tiny-keccak. The choice is driven by what
exists, not preference: ed25519-dalek and x25519-dalek are the de
facto reference Rust implementations of their respective primitives
and the only widely-audited independent stacks for Curve25519
arithmetic. RustCrypto's `ed25519` crate is a trait-only crate (it
defines `Signer<Signature>` and the encoded-signature shape) and does
not ship its own EdDSA implementation; RustCrypto has no first-party
X25519 crate at all. Selecting dalek keeps the verifier on a
maintained, independently-developed stack while preserving the "no
shared source with leviathan-crypto's WASM" property that the other
oracles rely on.

The Ed25519 verifier reads four files: `ed25519.ts` (RFC 8032 §7 KATs,
4 pure + 1 prehash, transcribed by hand from the RFC text and run
first as the gate), `ed25519_keygen.ts`, `ed25519_siggen.ts`, and
`ed25519_sigver.ts` (ACVP EDDSA-1.0 records filtered to the ed25519
curve only; ed448 is out of scope for v3). Per-record dispatch:

- keyGen: `SigningKey::from_bytes(&seed)` and compare
  `.verifying_key().to_bytes()` to ACVP `q`.
- sigGen pure: `SigningKey::sign(&message)` and compare to ACVP
  `signature`. The ed25519 sigGen corpus has context length 0 in
  every preHash=false record, so the verifier routes them through
  the bare `sign` path and never touches the (dalek-2.x-unavailable)
  Ed25519ctx signing API.
- sigGen prehash: build a `sha2::Sha512` digest pre-updated with
  the message and call `SigningKey::sign_prehashed(prehashed,
  Some(&context))`. Context may be empty.
- sigVer: `VerifyingKey::verify_strict` (pure) /
  `VerifyingKey::verify_prehashed_strict` (prehash). The boolean
  result is compared to ACVP `testPassed`.

**Strict-verification posture.** The verifier uses the `_strict`
variants exclusively, matching RFC 8032 §5.1.7 cofactored
verification, FIPS 186-5 §7.6.4, and ACVP `testPassed` semantics.
`_strict` rejects mixed-order public keys, small-order public keys,
and non-canonical scalars S; the non-strict `verify` would diverge
from `testPassed` on records that exercise those edge cases. The
RFC 8032 §7 gate corpus runs first; if it fails the ACVP corpus is
skipped (a transcription or oracle problem would otherwise look like
"signing works for some records but not others", which is a confusing
failure mode).

The X25519 verifier reads `x25519.ts` (RFC 7748 §5 iterated KATs at
iter=1 and iter=1000, plus the §6.1 Diffie-Hellman exchange between
Alice and Bob; iter=1000000 is omitted from the corpus, the runtime
is too long for a CI-fast verifier and the iter=1000 case already
catches the same correctness bugs). Per-record dispatch:

- Exchange: both directions of the DH must yield the same shared
  secret and must equal the RFC value;
  `StaticSecret::from(alice_sk).diffie_hellman(&PublicKey::from(bob_pk))`
  and the symmetric Bob-from-Alice path are computed, both compared
  to `shared`, and the round-trip
  `StaticSecret::from(alice_sk) → PublicKey` is checked against
  `alicePk` (and similarly for Bob) so the clamp + scalar-mult path
  is exercised, not just the final shared-secret bytes.
- Iterated: implement the RFC 7748 §5.2 loop in Rust over
  `x25519_dalek::x25519(scalar, u)` (the standalone primitive, not
  the Diffie-Hellman wrapper).

**X25519 all-zero shared secret.** x25519-dalek does NOT reject the
all-zero shared secret at the function-call level; the spec's §6
small-order rejection is the consumer's responsibility, and the RFC
explicitly allows that check to be performed by the application
above the primitive. The verifier's job here is byte agreement on
the raw scalar-mult output. Rejection-of-degenerate-public-keys is
exercised separately at the TypeScript layer, where the
leviathan-crypto wrapper checks for the all-zero shared secret and
throws.

Provenance for the five new files is recorded inline:

- RFC 8032: `https://www.rfc-editor.org/rfc/rfc8032.txt` (consumed
  by `ed25519.ts`; 4 §7.1 records + 1 §7.3 record, hand-transcribed).
- RFC 7748: `https://www.rfc-editor.org/rfc/rfc7748.txt` (consumed
  by `x25519.ts`; §6.1 exchange + §5 iter=1 + §5 iter=1000,
  hand-transcribed).
- ACVP EDDSA-KeyGen-1.0:
  `https://github.com/usnistgov/ACVP-Server/tree/15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0/gen-val/json-files/EDDSA-KeyGen-1.0`
  (consumed by `ed25519_keygen.ts`; 3 ed25519 AFT records;
  ed448 records filtered out at transcription time).
- ACVP EDDSA-SigGen-1.0:
  `https://github.com/usnistgov/ACVP-Server/tree/15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0/gen-val/json-files/EDDSA-SigGen-1.0`
  (consumed by `ed25519_siggen.ts`; 84 ed25519 records across 4
  groups: AFT pure 10, AFT prehash 10, BFT pure 32, BFT prehash 32).
- ACVP EDDSA-SigVer-1.0:
  `https://github.com/usnistgov/ACVP-Server/tree/15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0/gen-val/json-files/EDDSA-SigVer-1.0`
  (consumed by `ed25519_sigver.ts`; 10 ed25519 records, mixed
  pass/fail per `testPassed`, 5 AFT pure + 5 AFT prehash).

The ACVP-Server commit hash `15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0`
is the same snapshot already pinned for the SLH-DSA corpus
(slhdsa_keygen.ts, slhdsa_siggen.ts, slhdsa_sigver.ts). The
internalProjection.json files at this commit declare
`algorithm=EDDSA mode=keyGen|sigGen|sigVer revision=1.0`. FIPS 186-5
codifies EdDSA at the standards level but the ACVP-Server checkout
on disk does not currently expose an `EDDSA-...-FIPS186-5` directory;
the 1.0 corpus is the on-disk authority. Provenance follows the
on-disk state.

**KMAC and cSHAKE (SP 800-185).** Verified against:
- tiny-keccak's KMAC and cSHAKE implementations.

tiny-keccak is a separate Keccak permutation lineage from RustCrypto's `sha3` (used elsewhere in this verifier) and from leviathan-crypto's WASM Keccak. The byte-oriented `kmac.ts` corpus comprises 24 records across six variants: cSHAKE128 (4: 2 samples plus 2 ACVP AFT), cSHAKE256 (5: 2 samples plus 3 ACVP AFT), KMAC128 (5: 3 samples plus 2 ACVP MVT), KMAC256 (3 samples only), KMACXOF128 (3 samples only), KMACXOF256 (4: 3 samples plus 1 ACVP MVT). Sources: NIST CSRC sample PDFs (`cSHAKE_samples.pdf`, `KMAC_samples.pdf`, `KMACXOF_samples.pdf`) plus byte-aligned ACVP-Server records from `cSHAKE-128-1.0`, `cSHAKE-256-1.0`, `KMAC-128-1.0`, and `KMAC-256-1.0` (vsId=0 in each). The remaining ACVP cases are bit-level (key, message, MAC, or output lengths not divisible by 8) and are out of scope for leviathan-crypto's byte-oriented public API. They are filtered out at corpus build time and not pinned. The verifier independently reproduces every pinned record byte-for-byte against tiny-keccak. The reason for stepping outside the RustCrypto family for this one corpus is crate availability, not preference: RustCrypto's `kmac` crate is currently a 0.0.0 placeholder, and the pinned `sha3 = "=0.11.0"` does not yet expose `CShake`. tiny-keccak covers both in one crate and lands on a separate Keccak lineage, so the independence claim still holds.

**The combined invariant.** When all targets emit byte-identical output to the pinned KATs, two independent properties hold simultaneously: leviathan-crypto's symmetric seal wire format reproduces from independent RustCrypto primitives (the Tier 2 reproduction property for XChaCha20 v3 and Serpent v3), and the Tier 1 primitive vectors landed in the repo without transcription error against an independent codebase (the Tier 1 transcription property for AES across modes, POLYVAL, ML-KEM, and ML-DSA). RustCrypto and leviathan-crypto have no shared source code, no shared build system, and no shared person who wrote them. A bug in either stack that affects wire bytes, or a bad copy-paste of an ACVP record, would surface as a verifier mismatch.

---

## What the Verifier Does NOT Prove

Spelling out the limits of the audit is part of the audit.

**Constant-time properties are not verified.** RustCrypto's primitives are documented as constant-time on supported platforms; leviathan-crypto's WASM primitives are designed for constant-time execution. The verifier checks that they produce the same output bytes, which is a necessary condition for correctness. It does not measure timing variation or independently confirm constant-time behavior on either side. The `serpent_audit.md`, `chacha_audit.md`, and `sha2_audit.md` documents cover that scope separately.

**Side channels are out of scope.** Cache-timing, power analysis, EM emanation, and speculative-execution leaks are not within reach of byte-equality checking.

**WASM-internal memory safety is out of scope.** The verifier confirms that whatever leviathan-crypto produces on its output buffer matches what RustCrypto produces. It says nothing about whether leviathan-crypto's WASM linear memory is correctly wiped after use, whether transient buffers are scrubbed, or whether dispose paths free key material correctly. The unit and e2e test suites cover those properties via `test/unit/*/wipe.test.ts` and similar.

**Tier 1 vector files are not re-fetched.** The Tier 1 KAT files themselves are pinned by SHA-256 hash and treated as authoritative; the verifier's RustCrypto re-derivation is a transcription audit (catching copy-paste errors when records were ported into the repo), not a re-verification of NIST. A discrepancy between RustCrypto and the pinned `.ts` would point at the `.ts` first, not at the upstream record.

**Tier 3 vectors (ratchet, fortuna) are not covered.** No external reference exists to verify against; internal consistency tests in the unit suite cover the available correctness properties.

**KEM-wrapped seal blobs (Tier 4) are not covered as a single target.** The verifier independently covers the ML-KEM primitive against ACVP and covers symmetric Tier 2 wrappers, but it does not yet exercise KyberSuite-wrapped seal blobs end to end. Their two pieces are verified separately; their composition is not yet a single verifier target.

---

## Provenance of Pinned Vectors

The canonical inventory of every pinned vector file, Tier 1 and Tier 2 alike, lives in [`../test/vectors/README.md`](../test/vectors/README.md) and is mirrored in [`./test-suite.md`](./test-suite.md). SHA-256 pins for every file are recorded in [`../test/vectors/SHA256SUMS`](../test/vectors/SHA256SUMS), and the `hashsums` job in [`../.github/workflows/verify-vectors.yml`](../.github/workflows/verify-vectors.yml) fails the build on any mismatch.

The table below is the audit-doc-specific cut: the Tier 2 self-generated files the Rust verifier currently exercises end to end. They are produced by the generator scripts and pinned as KATs; the verifier re-derives every byte from primitives.

| File | Generator | Verifier coverage |
|---|---|---|
| `seal_xchacha_v3.ts` | `scripts/gen-seal-vectors.ts --cipher xchacha` | full |
| `seal_serpent_v3.ts` | `scripts/gen-seal-vectors.ts --cipher serpent` | full |
| `seal_aes_v3.ts` | `scripts/gen-seal-vectors.ts --cipher aes` | full |
| `sealstream_xchacha_v3.ts` | `scripts/gen-sealstream-vectors.ts --cipher xchacha` | full |
| `sealstream_serpent_v3.ts` | `scripts/gen-sealstream-vectors.ts --cipher serpent` | full |
| `sealstream_aes_v3.ts` | `scripts/gen-sealstream-vectors.ts --cipher aes` | full |

If a Tier 1 file needs to be refreshed (upstream errata, format change), download the new file, replace the local copy, regenerate `SHA256SUMS`, update the row in [`../test/vectors/README.md`](../test/vectors/README.md), and confirm the relevant unit-test job in `.github/workflows/` still passes.

---

## CI Integration

The `verify-vectors.yml` workflow runs two jobs, sequenced.

**Job 1: `hashsums`.** Reads `test/vectors/SHA256SUMS` and runs `sha256sum --check` against every pinned vector file. Catches accidental edits or supply-chain tampering of the corpus. Runs in under five seconds.

**Job 2: `rust-verify`.** Depends on `hashsums`. Builds the verifier crate at `scripts/verify-vectors/` with the pinned Rust toolchain (1.95.0) and the pinned dependency lockfile, then runs the verifier across twelve cipher targets: `xchacha`, `serpent`, `aes-seal`, `aes-gcm-siv`, `polyval`, `aes`, `aes-cbc`, `aes-ctr`, `aes-gcm`, `mlkem`, `mldsa`, and `kmac`. Each target dispatches to its `--target` scope (`seal`, `sealstream`, `keygen`, `siggen`, `sigver`, or `all`, depending on the cipher). Caches `~/.cargo/registry` and `target/` between runs via `Swatinem/rust-cache`. Cold builds take roughly 60 seconds; cached runs complete in under 15.

Both jobs are gated by `workflow_call` and triggered by the parent `test-suite.yml`. They run on every PR.

**Reading a green result.** Both jobs report `✓`. The verifier prints `✓ all vectors verified` as the final line.

**Reading a red result.** If `hashsums` fails, a vector file was modified in the working copy without regenerating `SHA256SUMS`. Either revert the change or run `cd test/vectors && sha256sum *.ts *.txt > SHA256SUMS` and commit. If `rust-verify` fails, the bytes the verifier computed do not match the pinned KATs. This is a real signal, either the generator script changed (review the diff), the vector file was edited by hand (forbidden by `AGENTS.md`), or the underlying primitive has shifted in a way that breaks reproducibility. Investigate before merging.

---

## How to Add a New Cipher

AES and ML-DSA both shipped following these recipes. AES landed as a Tier 1 family (block, CBC, CTR, GCM, GCM-SIV) plus POLYVAL, with five primitive verifier targets. ML-DSA landed as a Tier 1 ACVP target reading three vector files (`mldsa_keygen.ts`, `mldsa_siggen.ts`, `mldsa_sigver.ts`). The AES Tier 2 seal and sealstream wrappers shipped on top of the existing `aes-gcm-siv` primitive target, reusing the pinned `aes-gcm-siv` crate as the per-chunk AEAD.

For a new Tier 2 wrapper (any future cipher's seal wrapper):

1. Add the cipher's RustCrypto crate to `scripts/verify-vectors/Cargo.toml` with an exact-version pin, or reuse an already-pinned primitive crate.
2. Create `scripts/verify-vectors/src/<cipher>_seal.rs` modeled after `xchacha.rs` or `serpent.rs`. The shape is fixed: a `derive_v<N>` function for HKDF key derivation, a `seal_chunk_<cipher>` helper that calls the per-chunk AEAD, a `check_preamble` for the per-cipher invariants (format byte, 32-byte commitment), and `verify_seal` plus `verify_sealstream` entry points.
3. Add a `mod <cipher>_seal;` to `main.rs` and wire `run_<cipher>_seal` / `run_<cipher>_sealstream` into the dispatcher and the `--cipher` CLI flag.
4. Run `cargo run --release --cipher <cipher>` against the pinned KATs. Confirm the verifier reports green against every record.
5. Update the Tier 2 self-generated files table in this document, flipping coverage from "not yet" to "full".

For a new Tier 1 primitive (block cipher, mode, hash, MAC, KEM, signature scheme):

1. Add the RustCrypto crate to `Cargo.toml` with an exact-version pin and the audit comment block describing what it oracles.
2. Create `scripts/verify-vectors/src/<primitive>.rs` modeled after `aes.rs` (symmetric) or `mldsa.rs` (signature). Signature schemes need three vector types per ACVP convention: `keyGen` (compare pk + sk), `sigGen` (rebuild M' per signatureInterface and preHash, compare signature bytes), `sigVer` (decode pk + sig, compare boolean against ACVP `testPassed`).
3. Add a `mod <primitive>;` and the `--cipher` CLI flag entry.
4. Update the Tier 1 provenance table with the new file, source URL, and last-fetched date.

Notes. RustCrypto's `aes` crate matches NIST CAVP byte-exactly with no convention conversion. For ciphers not in RustCrypto's `aes` crate, byte-order conventions vary. Check both implementations' public APIs and the spec they cite before assuming a one-to-one byte-level mapping. Serpent is the working example: RustCrypto's `serpent` crate uses NIST natural byte order at its public API, leviathan-crypto v3's `Serpent` API uses NIST natural byte order as well, and the verifier feeds keys, IVs, and plaintext blocks through unchanged at the block-cipher boundary. leviathan-crypto v2 used the AES-submission floppy byte order at its public API and required a byte-reversal at the block-cipher boundary; v3 removes that asymmetry. The `ml-kem` and `ml-dsa` crates both ship as `0.x` pre-release versions; pin the exact version and audit the API surface on every major bump, especially `sign_internal` / `sign_mu_*` / `decapsulate_slice` and any FIPS 204 Appendix D domain-separation changes. Oracle crate selection now spans multiple lineages: most primitives use RustCrypto, KMAC and cSHAKE use `tiny-keccak`. A future maintainer adding a new cipher should check whether a working RustCrypto crate exists for the primitive and, if not, pick an alternate independent lineage rather than rolling a bespoke oracle.

---

## Cross-References

| Document | Description |
| -------- | ----------- |
| [audits](./audits.md) | Per-primitive correctness audits |
| [aead](./aead.md) | Authenticated encryption wire format and security model |
| [test-suite](./test-suite.md) | Full test inventory and gate structure |
| [architecture](./architecture.md) | Module layout, build pipeline, buffer layouts |
| [architectural-stance](./architectural-stance.md) | Architectural posture: defended threats, layer composition, and the framing constraint |
| [stream_audit](./stream_audit.md) | Streaming AEAD composition audit |
| [SECURITY.md](../SECURITY.md) | Security model, threat model, authenticator robustness |
