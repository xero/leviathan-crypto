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

**Tier 1: External authority.** Vectors come from NIST CAVP, NIST ACVP, RFC test appendices, or NESSIE. The vector files in `test/vectors/` are byte-for-byte copies of the upstream files, with provenance recorded below. These vectors define correctness for their primitives. Re-deriving them in another language is meaningless because the alternative implementation would itself be tested against the same vectors. The audit discipline is provenance, not re-verification: the upstream URL is recorded, the file checksum is pinned in `test/vectors/SHA256SUMS`, and any change requires a fresh download from the authoritative source.

**Tier 2: Self-generated over standard primitives.** Vectors encode wire formats designed by leviathan-crypto, but the underlying primitives are well-defined and have multiple independent implementations. The seal and sealstream KAT vectors live here. Re-deriving them in a different language with a different crypto stack is meaningful evidence the wire format claim holds. This is the target of the Rust verifier.

**Tier 3: Self-generated over custom primitives.** The construction is unique to leviathan-crypto and has no external reference implementation. The SPQR ratchet KATs and Fortuna PRNG KATs live here. The audit discipline is internal consistency: round-trip tests, never-reuse-nonce invariants, forward-secrecy property tests. Cross-language verification has no external authority to verify against.

**Tier 4: Hybrid.** Vectors that wrap a Tier 1 primitive in a Tier 2 construction. Kyber-suite seal blobs are an example. The KEM ciphertext piece is Tier 1 (NIST ACVP defines correctness). The seal-format wrapper is Tier 2 (we designed it). Today the verifier covers the Tier 2 piece for symmetric-only suites; KEM-wrapped vectors are not yet covered because adding `ml-kem` to the verifier's dependency graph adds API-volatile surface area for marginal value. NIST ACVP already covers the KEM independently.

---

## What the Verifier Proves

The Rust verifier at `scripts/verify-vectors/` re-derives every byte of every Tier 2 vector from primitives that share zero code with leviathan-crypto's WASM implementation. Specifically:

**XChaCha20 v3 seal and sealstream.** Verified against:
- HKDF-SHA-256 from RustCrypto's `hkdf` + `sha2` crates.
- HChaCha20 hand-rolled from RFC 8439 §2.3 in pure Rust with no external dependency.
- ChaCha20-Poly1305 from RustCrypto's `chacha20poly1305` crate.

The verifier independently computes the 32-byte key commitment from HKDF bytes 32..64 and asserts it matches the pinned preamble, then encrypts each chunk with the derived subkey and compares the wire bytes. Multi-chunk path verifies per-chunk counter increment, TAG_DATA versus TAG_FINAL flag handling, and framed-mode `u32be` length prefixes.

**Serpent v2 seal and sealstream.** Verified against:
- HKDF-SHA-256 from RustCrypto's `hkdf` + `sha2` crates (96-byte output).
- HMAC-SHA-256 from RustCrypto's `hmac` crate, used both for per-chunk IV derivation and for chunk authentication.
- Serpent block cipher from RustCrypto's `serpent = "0.6"` crate, separately confirmed byte-correct against NESSIE Set 1 vector#0 across all three key sizes (128/192/256).
- CBC chaining and PKCS#7 padding hand-rolled from spec.

leviathan-crypto's Serpent implementation uses the AES-submission "floppy" byte-order convention internally; RustCrypto's `serpent` crate uses the NESSIE convention. The two are reachable from each other by reversing all bytes of the key and each block (as documented in `test/unit/serpent/vector_parser.ts`). The verifier applies this transform at the block-cipher boundary, leaving CBC chaining math unaffected.

**The combined invariant.** When both verifiers (XChaCha20 and Serpent) emit byte-identical output to the pinned KATs, the wire format is reproducible across two independent crypto stacks. RustCrypto and leviathan-crypto have no shared source code, no shared build system, and no shared person who wrote them. A bug in either stack that affects wire bytes would surface as a verifier mismatch.

---

## What the Verifier Does NOT Prove

Spelling out the limits of the audit is part of the audit.

**Constant-time properties are not verified.** RustCrypto's primitives are documented as constant-time on supported platforms; leviathan-crypto's WASM primitives are designed for constant-time execution. The verifier checks that they produce the same output bytes, which is a necessary condition for correctness. It does not measure timing variation or independently confirm constant-time behavior on either side. The `serpent_audit.md`, `chacha_audit.md`, and `sha2_audit.md` documents cover that scope separately.

**Side channels are out of scope.** Cache-timing, power analysis, EM emanation, and speculative-execution leaks are not within reach of byte-equality checking.

**WASM-internal memory safety is out of scope.** The verifier confirms that whatever leviathan-crypto produces on its output buffer matches what RustCrypto produces. It says nothing about whether leviathan-crypto's WASM linear memory is correctly wiped after use, whether transient buffers are scrubbed, or whether dispose paths free key material correctly. The unit and e2e test suites cover those properties via `test/unit/*/wipe.test.ts` and similar.

**Tier 1 vectors are not re-verified.** The verifier targets Tier 2 only. NIST ACVP, NESSIE, and RFC appendix vectors are pinned by SHA-256 hash and treated as authoritative.

**Tier 3 vectors (ratchet, fortuna) are not covered.** No external reference exists to verify against; internal consistency tests in the unit suite cover the available correctness properties.

**KEM-wrapped seal blobs are not yet covered.** Symmetric XChaCha20 v3 and Serpent v2 are covered. KyberSuite blobs add an ML-KEM ciphertext to the preamble whose contents are deterministic from a seeded RNG; verifying them in Rust would require pulling RustCrypto's `ml-kem` crate in (currently pre-1.0). NIST ACVP covers the KEM piece independently.

---

## Provenance of Pinned Vectors

Tier 1 vector files in `test/vectors/`. Each row records the upstream source URL and the date the file was last fetched. The SHA-256 of every file is pinned in `test/vectors/SHA256SUMS`; the `verify-vectors.yml` workflow's `hashsums` job fails the build on any mismatch.

| File | Source | Last fetched |
|---|---|---|
| `serpent_ecb_vk.txt` | [AES submission floppy4](https://www.cl.cam.ac.uk/archive/rja14/serpent.html) | 2026-03-01 |
| `serpent_ecb_vt.txt` | AES submission floppy4 | 2026-03-01 |
| `serpent_ecb_tbl.txt` | AES submission floppy4 | 2026-03-01 |
| `serpent_ecb_iv.txt` | AES submission floppy4 | 2026-03-01 |
| `serpent_ecb_e_m.txt` | AES submission floppy4 | 2026-03-01 |
| `serpent_ecb_d_m.txt` | AES submission floppy4 | 2026-03-01 |
| `serpent_cbc_e_m.txt` | AES submission floppy4 | 2026-03-01 |
| `serpent_cbc_d_m.txt` | AES submission floppy4 | 2026-03-01 |
| `serpent_nessie-128.txt` | [NESSIE project](https://biham.cs.technion.ac.il/Reports/Serpent/) | 2026-03-01 |
| `serpent_nessie-192.txt` | NESSIE project | 2026-03-01 |
| `serpent_nessie-256.txt` | NESSIE project | 2026-03-01 |
| `chacha20.ts` | [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) §2.2.1 | 2026-03-01 |
| `kyber.ts` | NIST ACVP | 2026-03-01 |
| `kyber_keygen.ts` | NIST ACVP | 2026-03-01 |
| `kyber_encapdecap.ts` | NIST ACVP | 2026-03-01 |

Tier 2 self-generated files. These are produced by the generator scripts and pinned as KATs. The Rust verifier re-derives every byte from primitives.

| File | Generator | Verifier coverage |
|---|---|---|
| `seal_xchacha_v3.ts` | `scripts/gen-seal-vectors.ts --cipher xchacha` | full |
| `seal_serpent_v2.ts` | `scripts/gen-seal-vectors.ts --cipher serpent` | full |
| `sealstream_xchacha_v3.ts` | `scripts/gen-sealstream-vectors.ts --cipher xchacha` | full |
| `sealstream_serpent_v2.ts` | `scripts/gen-sealstream-vectors.ts --cipher serpent` | full |

If a Tier 1 file needs to be refreshed (upstream errata, format change), download the new file, replace the local copy, regenerate `SHA256SUMS`, update the "Last fetched" date in this table, and confirm the relevant unit-test job in `.github/workflows/` still passes.

---

## CI Integration

The `verify-vectors.yml` workflow runs two jobs, sequenced.

**Job 1: `hashsums`.** Reads `test/vectors/SHA256SUMS` and runs `sha256sum --check` against every pinned vector file. Catches accidental edits or supply-chain tampering of the corpus. Runs in under five seconds.

**Job 2: `rust-verify`.** Depends on `hashsums`. Builds the verifier crate at `scripts/verify-vectors/` with the pinned Rust toolchain (1.95.0) and the pinned dependency lockfile, then runs the verifier against every Tier 2 vector. Caches `~/.cargo/registry` and `target/` between runs via `Swatinem/rust-cache`. Cold builds take roughly 60 seconds; cached runs complete in under 15.

Both jobs are gated by `workflow_call` and triggered by the parent `test-suite.yml`. They run on every PR that touches `test/vectors/**`, `scripts/verify-vectors/**`, `scripts/gen-*-vectors.ts`, or the workflow file itself.

**Reading a green result.** Both jobs report `✓`. The verifier prints `✓ all vectors verified` as the final line.

**Reading a red result.** If `hashsums` fails, a vector file was modified in the working copy without regenerating `SHA256SUMS`. Either revert the change or run `cd test/vectors && sha256sum *.ts *.txt > SHA256SUMS` and commit. If `rust-verify` fails, the bytes the verifier computed do not match the pinned KATs. This is a real signal — either the generator script changed (review the diff), the vector file was edited by hand (forbidden by `AGENTS.md`), or the underlying primitive has shifted in a way that breaks reproducibility. Investigate before merging.

---

## How to Add a New Cipher

When AES lands as the new symmetric primitive, the verifier extension follows the same shape as Serpent. ML-DSA-44 will need different scaffolding because it's a signature scheme rather than an AEAD.

For a new symmetric cipher (AES, future Tier 2 additions):

1. Add the new cipher's RustCrypto crate to `scripts/verify-vectors/Cargo.toml` with an exact-version pin.
2. Create `scripts/verify-vectors/src/<cipher>.rs` modeled after `serpent.rs`. The shape is fixed: a `derive_v<N>` function, a `seal_chunk_<cipher>` helper, a `check_preamble` for the per-cipher invariants, and `verify_seal` plus `verify_sealstream` entry points.
3. Add a `mod <cipher>;` to `main.rs` and wire the new cipher into the `--cipher` CLI flag and the `run_<cipher>_seal` / `run_<cipher>_sealstream` dispatchers.
4. Run `cargo run --release` against the existing pinned KATs. The new path runs zero vectors but must compile and link cleanly.
5. Once the cipher's KAT vector files exist (`seal_<cipher>_vN.ts`, `sealstream_<cipher>_vN.ts`), add the parser-side type names to the dispatcher and run end to end.
6. Update the "Tier 2 self-generated files" table in this document with the new files and verifier coverage status.

Two cipher-specific concerns worth noting up front. RustCrypto's `aes` crate is the most-vetted block cipher in the entire RustCrypto ecosystem and matches NIST CAVP byte-exactly with no convention conversion. ML-DSA-44 will require coordination on the `ml-dsa` crate's stability and a different verification shape: signatures are deterministic from seed and message, so verification means re-running `sign(seed, msg)` and comparing the output byte-for-byte against a pinned signature.

---

## Cross-References

| Document | Description |
| -------- | ----------- |
| [audits](./audits.md) | Per-primitive correctness audits |
| [aead](./aead.md) | Authenticated encryption wire format and security model |
| [test-suite](./test-suite.md) | Full test inventory and gate structure |
| [architecture](./architecture.md) | Module layout, build pipeline, buffer layouts |
| [stream_audit](./stream_audit.md) | Streaming AEAD composition audit |
| [SECURITY.md](../SECURITY.md) | Security model, threat model, authenticator robustness |
