# Leviathan Crypto — Vector Corpus

<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="Leviathan logo" width="400">


## Vector Corpus

| File | Source | Vectors | Status |
|------|--------|---------|--------|
| `serpent_ecb_vt.txt` | [AES submission floppy4](https://www.cl.cam.ac.uk/archive/rja14/serpent.html) — variable text | 384 | VERIFIED |
| `serpent_ecb_vk.txt` | [AES submission floppy4](https://www.cl.cam.ac.uk/archive/rja14/serpent.html) — variable key | 576 | VERIFIED |
| `serpent_ecb_tbl.txt` | [AES submission floppy4](https://www.cl.cam.ac.uk/archive/rja14/serpent.html) — S-box table | 1536 | VERIFIED |
| `serpent_ecb_iv.txt` | [AES submission floppy4](https://www.cl.cam.ac.uk/archive/rja14/serpent.html) — intermediate values | 3 key sizes | VERIFIED |
| `serpent_ecb_e_m.txt` | [AES submission floppy4](https://www.cl.cam.ac.uk/archive/rja14/serpent.html) — ECB Monte Carlo encrypt | 1200 | VERIFIED |
| `serpent_ecb_d_m.txt` | [AES submission floppy4](https://www.cl.cam.ac.uk/archive/rja14/serpent.html) — ECB Monte Carlo decrypt | 1200 | VERIFIED |
| `serpent_cbc_e_m.txt` | [AES submission floppy4](https://www.cl.cam.ac.uk/archive/rja14/serpent.html) — CBC Monte Carlo encrypt | 1200 | VERIFIED |
| `serpent_cbc_d_m.txt` | [AES submission floppy4](https://www.cl.cam.ac.uk/archive/rja14/serpent.html) — CBC Monte Carlo decrypt | 1200 | VERIFIED |
| `serpent_nessie-128.txt` | [NESSIE project](https://biham.cs.technion.ac.il/Reports/Serpent/) | 1028 | VERIFIED |
| `serpent_nessie-192.txt` | [NESSIE project](https://biham.cs.technion.ac.il/Reports/Serpent/) | 1156 | VERIFIED |
| `serpent_nessie-256.txt` | [NESSIE project](https://biham.cs.technion.ac.il/Reports/Serpent/) | 1284 | VERIFIED |
| `serpent.ts` | SerpentStream round-trip fixture (3 × 1024-byte chunks) | 1 | VERIFIED (Gate 9) |
| `serpent_composition.ts` | [Self-generated](https://github.com/xero/leviathan-crypto/blob/main/scripts/gen-seal-vectors.ts) — SerpentSeal (TC1, TC2) and SerpentStream (SS-1, SS-3, SS-6) KAT vectors. Generated with fixed IV/nonce seams, decomposed and verified against underlying primitives independently. | 5 | SELF-GENERATED |
| `serpent_stream_sealer.ts` | [Self-generated](https://github.com/xero/leviathan-crypto/blob/main/scripts/gen-sealstream-vectors.ts) — SerpentStreamSealer/Opener (SS1, SS2, SS3) KAT vectors. Generated with fixed nonce/IV seams, decomposed and verified against SerpentCbc + HMAC_SHA256 + HKDF_SHA256 independently. | 3 | SELF-GENERATED |
| `serpent_stream_encoder.ts` | [Self-generated](https://github.com/xero/leviathan-crypto/blob/main/scripts/gen-streamencoder-vectors.ts) — SerpentStreamEncoder/Decoder (SE1, SE2, SE3) KAT vectors. Generated with fixed nonce/IV seams, verified by round-trip through SerpentStreamDecoder (single feed + byte-at-a-time). | 3 | SELF-GENERATED |
| `shake_xof.ts` | [Self-generated](https://github.com/xero/leviathan-crypto/blob/main/test/vectors/shake_xof.ts) — SHAKE128/256 multi-squeeze vectors (MS-1–MS-9). All chunks are slices of externally-verified KATs from `sha3.ts`, verified against Node.js `crypto.createHash`. | 8 | SELF-GENERATED |
| `chacha20.ts` | [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) §2.2.1 — ChaCha20 block function | 1 | VERIFIED (Gate 3) |
| `chacha20.ts` | [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) §2.4.2 — ChaCha20 114-byte encryption | 1 | VERIFIED |
| `chacha20.ts` | [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) §2.5.2 — Poly1305 34-byte message | 1 | VERIFIED (Gate 4) |
| `chacha20.ts` | [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) §2.6.2 — Poly1305 key generation | 1 | VERIFIED |
| `chacha20.ts` | [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) §A.3 — Poly1305 TV #1–#6 | 6 | VERIFIED |
| `chacha20.ts` | [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) §2.8.2 — ChaCha20-Poly1305 sunscreen AEAD | 1 | VERIFIED (Gate 5) |
| `chacha20.ts` | [draft-irtf-cfrg-xchacha-03](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03) §A.3.1 — HChaCha20 subkey | 1 | VERIFIED (Gate 6) |
| `chacha20.ts` | [draft-irtf-cfrg-xchacha-03](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03) §A.3.2 — XChaCha20-Poly1305 AEAD | 1 | VERIFIED |
| `sha2.ts` | [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) §B.1 — SHA-256 "abc" | 1 | VERIFIED |
| `sha2.ts` | [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) §B.2 — SHA-256 448-bit message | 1 | VERIFIED |
| `sha2.ts` | [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) §B.3 — SHA-256 "a" × 1M | 1 | VERIFIED |
| `sha2.ts` | [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) — SHA-256 boundary cases (empty, 55B, 56B, 64B) | 4 | VERIFIED |
| `sha2.ts` | [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) §C.1–C.3 — SHA-512 spec vectors | 4 | VERIFIED |
| `sha2.ts` | [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) — SHA-512 boundary cases (empty, 111B, 112B, 128B) | 3 | VERIFIED |
| `sha2.ts` | [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) §D.1–D.2 — SHA-384 spec vectors | 3 | VERIFIED |
| `sha2.ts` | [RFC 4231](https://www.rfc-editor.org/rfc/rfc4231) §4.2/§4.3/§4.7 — HMAC-SHA256 TC1, TC2, TC6 | 3 | VERIFIED |
| `sha2.ts` | [RFC 4231](https://www.rfc-editor.org/rfc/rfc4231) §4.2/§4.3/§4.7 — HMAC-SHA512 TC1, TC2, TC6 | 3 | VERIFIED |
| `sha2.ts` | [RFC 4231](https://www.rfc-editor.org/rfc/rfc4231) §4.2/§4.3/§4.7 — HMAC-SHA384 TC1, TC2, TC6 | 3 | VERIFIED |
| `sha2.ts` | [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) §A.1/§A.2/§A.3 — HKDF-SHA256 | 3 | VERIFIED |
| `sha2.ts` | Node.js crypto.hkdfSync — HKDF-SHA512 (same inputs as RFC A.1–A.3) | 3 | VERIFIED |
| `sha3.ts` | [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) §A.1 — SHA3-256 (empty, "abc", 448-bit) | 3 | VERIFIED |
| `sha3.ts` | [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) — SHA3-256 rate boundary cases (135B, 136B, 137B) | 3 | VERIFIED |
| `sha3.ts` | [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) §A.4 — SHA3-512 (empty, "abc") | 2 | VERIFIED |
| `sha3.ts` | [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) — SHA3-512 rate boundary cases (71B, 72B, 73B) | 3 | VERIFIED |
| `sha3.ts` | [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) — SHA3-384 (empty, "abc") + rate boundary (103B, 104B) | 4 | VERIFIED |
| `sha3.ts` | [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) — SHA3-224 (empty, "abc") + rate boundary (143B, 144B) | 4 | VERIFIED |
| `sha3.ts` | [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) — SHAKE128 (empty×32, "abc"×32, empty×64, rate boundary) | 5 | VERIFIED |
| `sha3.ts` | Node.js crypto / Python hashlib — SHAKE128 multi-block (empty×200, empty×336, empty×400, "abc"×200) | 4 | VERIFIED |
| `sha3.ts` | [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) — SHAKE256 (empty×32, "abc"×64, rate boundary) | 4 | VERIFIED |
| `sha3.ts` | Node.js crypto / Python hashlib — SHAKE256 multi-block (empty×200, empty×272, empty×300, "abc"×200) | 4 | VERIFIED |

> [!IMPORTANT]
> All vector files are read-only. Integrity is verified via [`SHA256SUMS`](https://github.com/xero/leviathan-crypto/blob/main/test/vectors/SHA256SUMS)
> with expected values sourced directly from authoritative references.
> They are the **_immutable truth,_** and must never be modified to make tests pass.

> [!NOTE]
> `serpent_composition.ts`, `serpent_stream_sealer.ts`, `serpent_stream_encoder.ts`, and
> `shake_xof.ts` are self-generated — there is no external authority for these wire formats
> or multi-squeeze output slices. Each was produced with fixed inputs and independently
> verified against the underlying primitives. These vectors are regression trip-wires for
> format stability, not proof of correctness against an external reference. Generation
> scripts are kept in the repo so derivations can be audited or reproduced.

See: [test-suite](https://github.com/xero/leviathan-crypto/wiki/test-suite) for our full testing methodology
