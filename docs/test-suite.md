# Test Suite & Vector Corpus

<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/test-suite.svg" alt="Test Suite Date Flow Diagram" width="800">

## Test Counts

| Runner | Tests | Status |
|--------|-------|--------|
| Vitest (unit) | 415 | All pass |
| Playwright (e2e) | 135 (45 tests × 3 browsers) | All pass |
| **Total** | **550** | |

---

## Unit Tests (Vitest)

| File | Description | Vectors / Tests | Gate |
|------|-------------|-----------------|------|
| `init.test.ts` | `init()` API: embedded, manual, idempotent, error-before-init | 9 | — |
| `serpent/serpent_sbox.test.ts` | S-box table entries (serpent_ecb_tbl.txt) | 1536 vectors, 2 tests | Gate 1 |
| `serpent/serpent_iv.test.ts` | Key schedule intermediate values (serpent_ecb_iv.txt) | 3 key sizes, 2 tests | Gate 2 |
| `serpent/serpent_kat.test.ts` | KAT variable-text + variable-key (serpent_ecb_vt/vk.txt) | 960 vectors, 6 tests | — |
| `serpent/serpent_nessie128.test.ts` | NESSIE 128-bit vectors | 1028 vectors, 3 tests | — |
| `serpent/serpent_nessie192.test.ts` | NESSIE 192-bit vectors | 1156 vectors, 3 tests | — |
| `serpent/serpent_nessie256.test.ts` | NESSIE 256-bit vectors | 1284 vectors, 3 tests | — |
| `serpent/serpent_ctr.test.ts` | CTR mode cases A–E | 5 tests | — |
| `serpent/serpent_wipe.test.ts` | wipeBuffers() verification | 1 test | — |
| `serpent/serpent_cbc.test.ts` | CBC padding, round-trip, validation | 24 tests | — |
| `serpent/serpent.test.ts` | SerpentSeal round-trip, tag/ciphertext/IV corruption, non-deterministic IV, key-length and data-too-short RangeErrors, dispose, init guards (serpent missing, sha2 missing), SerpentCbc/SerpentCtr dangerUnauthenticated gate | 15 tests | — |
| `serpent/serpent_montecarlo.test.ts` | ECB Monte Carlo (1200 × 10000 enc + dec) | 2400 outer, 4 tests | — |
| `serpent/serpent_cbc_montecarlo.test.ts` | CBC Monte Carlo (1200 × 10000 enc + dec) | 2400 outer, 4 tests | — |
| `serpent/serpent_stream.test.ts` | SerpentStream round-trip, auth, position binding, validation, lifecycle | 19 tests | Gate 9 |
| `serpent/serpent_stream_pool.test.ts` | SerpentStreamPool correctness, parallel, auth, lifecycle | 15 tests | Gate 10 |
| `serpent/serpent_stream_sealer.test.ts` | SerpentStreamSealer/Opener: KAT (SS1–SS3), round-trip, tamper, truncation, cross-stream splice, reorder, state machine guards, lifecycle | 21 tests | Gate 11 |
| `serpent/serpent_stream_encoder.test.ts` | SerpentStreamEncoder/Decoder: KAT (SE1–SE3), length prefix, byte-at-a-time feed, split feed, multi-frame feed, post-final leftover, tamper, cross-stream, reorder, state machine, lifecycle | 22 tests | Gate 12 |
| `serpent/serpent_seal_kat.test.ts` | SerpentSeal KAT: known-answer (TC1, TC2), auth failure (ciphertext + tag), round-trip | 6 tests | — |
| `serpent/serpent_stream_kat.test.ts` | SerpentStream KAT: known-answer (SS-1, SS-3, SS-6), header field decomposition, per-chunk tag verification, truncation, reorder, cross-stream splice, auth failure, min/max chunk size round-trip | 12 tests | — |
| `chacha20/chacha20.test.ts` | ChaCha20 block + encryption + round-trips | 6 tests | Gate 3 |
| `chacha20/poly1305.test.ts` | Poly1305 MAC vectors (§2.5.2, §2.6.2, A.3 #1–#6) | 9 tests | Gate 4 |
| `chacha20/chacha20poly1305.test.ts` | ChaCha20-Poly1305 AEAD (§2.8.2, round-trips, tamper, validation) | 16 tests | Gate 5 |
| `chacha20/xchacha20.test.ts` | XChaCha20-Poly1305 (HChaCha20, §A.3.2, round-trips, tamper, validation) | 14 tests | Gate 6 |
| `chacha20/pool.test.ts` | XChaCha20Poly1305Pool correctness, parallel, auth, lifecycle | 21 tests | — |
| `sha2/sha256.test.ts` | SHA-256 vectors, streaming, wipeBuffers, leviathan cross-check | 11 tests | Gate 3 |
| `sha2/sha512.test.ts` | SHA-512, SHA-384 vectors, streaming, leviathan cross-check | 14 tests | Gate 4 |
| `sha2/hmac.test.ts` | HMAC-SHA256/512/384 vectors, leviathan cross-check | 14 tests | Gate 5, 6 |
| `sha2/hkdf.test.ts` | HKDF-SHA256 RFC 5869 A.1-A.3, HKDF-SHA512 generated vectors, extract/expand isolation, derive consistency, RangeError guards, salt defaults, dispose | 22 tests | Gate 8 |
| `sha3/sha3.test.ts` | SHA3-224/256/384/512, SHAKE128/256 (single + multi-block), incremental absorb/squeeze, state machine guards, dispose zeroes TS buffer, wipeBuffers, leviathan cross-check | 61 tests | Gate 7 |
| `sha3/shake_xof.test.ts` | SHAKE128/256 multi-squeeze KAT: rate-boundary crossing (MS-1–3, MS-5–7), byte-by-byte squeeze (MS-4, MS-8), reset after multi-squeeze (MS-9) | 10 tests | — |
| `fortuna.test.ts` | Fortuna CSPRNG: create, get, entropy, stop/start, key replacement, pool selection | 11 tests | — |
| `utils.test.ts` | hex, utf8, base64 encoding, constantTimeEqual, wipe, xor, concat, randomBytes | 30 tests | — |

---

## E2E Tests (Playwright)

45 tests × 3 browsers (Chromium, Firefox, WebKit) = 135 total.

| File | Description | Vectors |
|------|-------------|---------|
| `serpent_kat.spec.ts` | KAT vt (384) + vk (576) + decrypt (384) + S-box (1536) | 2880 |
| `serpent_iv.spec.ts` | Intermediate values — final CT for 3 key sizes | 3 |
| `serpent_nessie.spec.ts` | NESSIE 256-bit (1284) + 128-bit (1028) | 2312 |
| `serpent_ctr.spec.ts` | CTR mode cases A–E | 5 |
| `serpent_montecarlo.spec.ts` | ECB MC + CBC MC enc + CBC MC dec (50 outer × 10000 inner) | ~150 |
| `chacha20.spec.ts` | ChaCha20 RFC §2.4.2 encryption + 128B round-trip | 2 |
| `poly1305.spec.ts` | Poly1305 RFC §2.5.2 gate + wipeBuffers verification | 2 |
| `chacha20poly1305.spec.ts` | ChaCha20-Poly1305 RFC §2.8.2 sunscreen AEAD + round-trip | 2 |
| `xchacha20.spec.ts` | XChaCha20-Poly1305 draft §A.3.2 AEAD + round-trip | 2 |
| `sha256.spec.ts` | SHA-256 empty (Gate 3), "abc", streaming 4×64B | 3 |
| `sha512.spec.ts` | SHA-512 "abc" (Gate 4), SHA-384 "abc", streaming 4×128B | 3 |
| `hmac.spec.ts` | HMAC-SHA256 TC1 (Gate 5), HMAC-SHA512 TC6 (Gate 6), HMAC-SHA256 TC2 | 3 |
| `sha3.spec.ts` | SHA3-256 empty (Gate 7), SHA3-512 "abc", SHAKE128 empty/32B | 3 |
| `serpent_stream_pool.spec.ts` | SerpentStreamPool cross-compat, round-trip, tamper, size | 5 |
| `xchacha20_pool.spec.ts` | XChaCha20Poly1305Pool cross-compat, round-trip, tamper, size | 5 |

> [!NOTE]
> E2E Monte Carlo tests use 50 outer iterations in Playwright (vs 1200 in Vitest) for
> cross-browser performance. A correct 50-iteration result is strong evidence of
> correct 1200-iteration behavior as errors compound within the first few iterations.

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
> All vector files are read-only. Integrity is verified via [`SHA256SUMS`](https://github.com/xero/lvthn/blob/main/test/vectors/SHA256SUMS)
> with expected values sourced directly from authoritative references.
> They are the **_immutable truth,_** and must never be modified to make tests pass.

> [!NOTE]
> `serpent_composition.ts` vectors are self-generated — there is no external authority for the
> SerpentSeal and SerpentStream wire formats. They were produced by running
> [`scripts/gen-seal-vectors.ts`](https://github.com/xero/leviathan-crypto/blob/main/scripts/gen-seal-vectors.ts)
> with fixed IV/nonce seams, then independently verifying each output against the underlying
> primitives (SerpentCbc, SerpentCtr, HMAC_SHA256, HKDF_SHA256). These vectors are regression
> trip-wires for wire format stability, not proof of correctness against an external reference.
> The generation script is kept in the repo so the derivation can be audited or reproduced.

## Cross-References

- [README.md](./README.md) — documentation index and quick-start guide
- [architecture.md](./architecture.md) — library architecture, module structure, and correctness contracts
- [serpent.md](./serpent.md) — Serpent-256 TypeScript API (tested primitives)
- [chacha20.md](./chacha20.md) — ChaCha20/Poly1305 TypeScript API (tested primitives)
- [sha2.md](./sha2.md) — SHA-2/HMAC/HKDF TypeScript API (tested primitives)
- [sha3.md](./sha3.md) — SHA-3/SHAKE TypeScript API (tested primitives)
- [fortuna.md](./fortuna.md) — Fortuna CSPRNG (tested primitive)
- [utils.md](./utils.md) — encoding utilities and `constantTimeEqual` (tested primitives)
- [types.md](./types.md) — public interfaces verified by the test suite
