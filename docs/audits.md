<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### Cryptographic Audits

Independent correctness and security reviews of every primitive in leviathan-crypto. Each audit verifies the implementation against its authoritative specification using published known-answer test vectors.

---

| Primitive | Conducted | Description |
|---|---|---|
| [serpent_audit](./serpent_audit.md) | 2026-03-09 | Correctness verification, side-channel analysis, cryptanalytic attack paper review |
| [chacha_audit](./chacha_audit.md) | 2026-03-25 | XChaCha20-Poly1305 correctness, Poly1305 field arithmetic, HChaCha20 nonce extension |
| [sha2_audit](./sha2_audit.md) | 2026-03-25 | SHA-256/512/384 correctness, HMAC and HKDF composition, constant verification |
| [sha3_audit](./sha3_audit.md) | 2026-03-25 | Keccak permutation correctness, step verification, round constant derivation |
| [hmac_audit](./hmac_audit.md) | 2026-03-25 | HMAC construction, key processing, RFC 4231 vector coverage |
| [hkdf_audit](./hkdf_audit.md) | 2026-03-25 | Extract-and-expand, info field domain separation, stream key derivation |
| [kyber_audit](./kyber_audit.md) | 2026-04-06 | ML-KEM FIPS 203 correctness, NTT verification, FO transform CT analysis, ACVP validation |
| [stream_audit](./stream_audit.md) | 2026-04-03 | Streaming AEAD composition, counter nonce binding, final-chunk detection, key wipe paths |
| [ratchet_audit](./ratchet_audit.md) | 2026-04-13 | SPQR KDF primitives: HKDF parameter assignments, wipe coverage, counter encoding, direction slot alignment |
| [vector_audit](./vector_audit.md) | 2026-05-04 | Test vector tier classification, independent Rust verifier coverage, CI integration, provenance of pinned KATs |
| [mldsa_audit](./mldsa_audit.md) | 2026-05-13 | ML-DSA FIPS 204 correctness across ML-DSA-44/65/87, HashML-DSA prehashed-input surface, signing and verification paths, ACVP validation |
| [slhdsa_audit](./slhdsa_audit.md) | 2026-05-14 | SLH-DSA FIPS 205 correctness for the SHAKE-fast parameter sets (128f/192f/256f) plus the three PQ-only hybrid suites: buffer layout, ADRS, WOTS+/FORS/XMSS/hypertree, top-level §9 algorithms, ACVP validation |
| [blake3_audit](./blake3_audit.md) | 2026-05-15 | BLAKE3 spec conformance: v128 compress and lane-parallel compress4, chunk machine, subtree stack and root finalize, keyed_hash and derive_key modes, XOF squeeze, memory hygiene |
| [ed25519_audit](./ed25519_audit.md) | 2026-05-16 | Ed25519 RFC 8032 plus FIPS 186-5 §7.6.4 strict verification, fault-injection defence, embedded SHA-512 integrity, constant-time discipline, dom2 prehash binding |
| [x25519_audit](./x25519_audit.md) | 2026-05-16 | X25519 RFC 7748 §5 clamping discipline, constant-time Montgomery ladder, TS-layer all-zero shared-secret rejection, RFC 7748 §6.1 plus iter=1000 vector coverage |
| [ecdsa-p256_audit](./ecdsa-p256_audit.md) | 2026-05-17 | ECDSA-P256 FIPS 186-5 §6 strict verification, RFC 6979 §3.2 deterministic-K gate, `draft-irtf-cfrg-det-sigs-with-noise-05` hedged-by-default posture, RFC 6979 §3.5 low-S enforcement on signer and verifier, fault-injection defence, embedded SHA-256 + HMAC-SHA-256 integrity, suite-layer integration |

---

## Cross-References

| Document | Description |
| -------- | ----------- |
| [index](./README.md) | Project Documentation index |
| [architecture](./architecture.md) | architecture overview, module relationships, buffer layouts, and build pipeline |

