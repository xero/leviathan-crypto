# Cryptographic Audits

> [!NOTE]
> Independent correctness and security reviews of every primitive in leviathan-crypto. Each audit verifies the implementation against its authoritative specification using published known-answer test vectors.

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

---

## Cross-References

| Document | Description |
| -------- | ----------- |
| [index](./README.md) | Project Documentation index |
| [architecture](./architecture.md) | architecture overview, module relationships, buffer layouts, and build pipeline |

