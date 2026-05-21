<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### ASM Layer Internal Import Graph

Per-module import dependency trees for the AssemblyScript sources under `src/asm/`. Each WASM module is fully independent at the binary level (no cross-module imports), but the files inside each module form a small dependency DAG documented below. Buffer-offset getters from `buffers.ts` flow into every consumer; mode files (CBC, CTR, GCM, etc.) consume the core block-cipher / hash primitives.

For the high-level relationship between modules and the public TypeScript surface, see [architecture.md](./architecture.md#module-relationships). For per-file source-level descriptions, see the AssemblyScript layer tree in [architecture.md](./architecture.md#assemblyscript-layer).

---

**Serpent (`src/asm/serpent/`)**

```
buffers.ts
  <- serpent.ts            (offsets for key, block, subkey, work, CBC IV)
  <- serpent_unrolled.ts   (block offsets, subkey, work)
  <- serpent_simd.ts       (SIMD bitsliced block operations)
  <- cbc.ts                (IV, block, chunk offsets)
  <- cbc_simd.ts           (SIMD CBC decrypt)
  <- ctr.ts                (nonce, counter, block, chunk offsets)
  <- ctr_simd.ts           (SIMD CTR 4-wide inter-block)

serpent.ts
  <- serpent_unrolled.ts   (S-boxes sb0-sb7, si0-si7, lk, kl, keyXor)

serpent_unrolled.ts
  <- cbc.ts                (encryptBlock_unrolled, decryptBlock_unrolled)
  <- ctr.ts                (encryptBlock_unrolled)

serpent_simd.ts
  <- cbc_simd.ts           (SIMD block operations)
  <- ctr_simd.ts           (SIMD block operations)

index.ts
  re-exports: buffers + serpent + serpent_unrolled + serpent_simd + cbc + cbc_simd + ctr + ctr_simd
```

**ChaCha (`src/asm/chacha20/`)**

```
buffers.ts
  <- chacha20.ts           (key, nonce, counter, block, state, poly key, xchacha offsets)
  <- chacha20_simd_4x.ts   (SIMD work buffer, chunk offsets)
  <- poly1305.ts           (poly key, msg, buf, tag, h, r, rs, s offsets)
  <- wipe.ts               (all buffer offsets, zeroes everything)

index.ts
  re-exports: buffers + chacha20 + chacha20_simd_4x + poly1305 + wipe
```

**AES (`src/asm/aes/`)**

```
buffers.ts
  <- aes.ts                (key, block PT/CT, 8x parallel blocks, round keys, bitsliced state, scratch, NR, GCM/SIV state)
  <- sbox.ts               (BITSLICED_STATE_OFFSET, CANRIGHT_SCRATCH_OFFSET)
  <- cbc.ts                (key, IV, chunk offsets)
  <- cbc_simd.ts           (SIMD CBC decrypt block offsets)
  <- ctr.ts                (nonce, counter, block, chunk offsets)
  <- ctr_simd.ts           (SIMD CTR 8-wide inter-block)
  <- gcm.ts                (H, J0, GHASH accumulator, AAD, tag, lengths, scratch)
  <- ghash.ts              (GHASH accumulator + scratch)
  <- gf128.ts              (4-bit windowed multiply table)
  <- polyval.ts            (POLYVAL hash subkey + accumulator)
  <- aes-gcm-siv.ts        (POLYVAL auth/enc keys, initial counter)
  <- wipe.ts               (all buffer offsets, zeroes everything)

aes.ts
  <- (block primitives consumed by cbc, ctr, gcm, aes-gcm-siv)

sbox.ts
  <- aes.ts                (sboxBitsliced, invSboxBitsliced)

ghash.ts
  <- gcm.ts                (ghashStart, ghashAbsorb*)

gf128.ts
  <- ghash.ts              (gf128InitTable, gf128MulH)
  <- polyval.ts            (mulXGhash for POLYVAL byte-reversal bridge)

polyval.ts
  <- aes-gcm-siv.ts        (polyvalStart, polyvalAbsorb, polyvalFinalize)

index.ts
  re-exports: buffers + aes + cbc + cbc_simd + ctr + ctr_simd + gcm + ghash + polyval + aes-gcm-siv + wipe
```

**SHA-2 (`src/asm/sha2/`)**

```
buffers.ts
  <- sha256.ts             (H, block, W, out, input, partial, total offsets)
  <- sha512.ts             (H, block, W, out, input, partial, total offsets)
  <- hmac.ts               (SHA-256 input, out, ipad, opad, inner offsets)
  <- hmac512.ts            (SHA-512 input, out, ipad, opad, inner offsets)

sha256.ts
  <- hmac.ts               (sha256Init, sha256Update, sha256Final)

sha512.ts
  <- hmac512.ts            (sha512Init, sha384Init, sha512Update, sha512Final, sha384Final)

index.ts
  re-exports: buffers + sha256 + sha512 + hmac + hmac512
  defines: wipeBuffers() inline
```

**SHA-3 (`src/asm/sha3/`)**

```
buffers.ts
  <- keccak.ts             (state, rate, absorbed, dsbyte, input, out offsets)

index.ts
  re-exports: buffers + keccak
```

**Kyber (`src/asm/kyber/`)**

```
params.ts
  <- reduce.ts             (Q, QINV, BARRETT_V, BARRETT_SHIFT)
  <- poly.ts               (Q, POLY_BYTES, HALF_Q, compression constants)
  <- polyvec.ts            (Q, POLY_BYTES, compression constants)
  <- sampling.ts           (Q)

buffers.ts
  <- polyvec.ts            (POLY_ACC_OFFSET)

reduce.ts
  <- ntt.ts                (fqmul, barrett_reduce)
  <- ntt_simd.ts           (fqmul, barrett_reduce, scalar tail)
  <- poly.ts               (montgomery_reduce, barrett_reduce, fqmul)

ntt.ts
  <- ntt_simd.ts           (getZetasOffset, zetas table pointer)
  <- poly.ts               (ntt, invntt, basemul, getZeta)

ntt_simd.ts
  <- poly_simd.ts          (ntt_simd, invntt_simd, barrett_reduce_8x)

poly.ts
  <- polyvec.ts            (poly_tobytes, poly_frombytes, poly_basemul_montgomery)

poly_simd.ts
  <- polyvec.ts            (poly_add_simd, poly_reduce_simd, poly_ntt_simd, poly_invntt_simd)

cbd.ts
  <- poly.ts               (cbd2, cbd3)

index.ts
  re-exports: buffers + ntt (scalar aliases) + ntt_simd (as ntt/invntt) +
              reduce + poly (scalar serialization/compression/basemul) +
              poly_simd (as poly_add/sub/reduce/ntt/invntt) +
              polyvec + sampling + verify
```

**ML-DSA (`src/asm/mldsa/`)**

```
params.ts
  <- reduce.ts             (Q=8380417, QINV, MONT, BARRETT constants)
  <- poly.ts               (γ₁/γ₂/η/β/τ/ω/λ per parameter set)
  <- sampling.ts           (matrix Â and noise sampling parameters)
  <- rounding.ts           (γ₂ for Decompose/HighBits/LowBits/MakeHint/UseHint)

buffers.ts
  <- poly.ts, polyvec.ts, sampling.ts, rounding.ts, encoding.ts (slot offsets)

reduce.ts
  <- ntt.ts, ntt_simd.ts, poly.ts (montgomery_reduce, barrett_reduce, fqmul over q)

ntt.ts
  <- ntt_simd.ts, poly.ts (8-layer NTT over T_q, scalar entry points)

ntt_simd.ts
  <- poly_simd.ts (v128 i32 butterflies)

poly.ts, poly_simd.ts
  <- polyvec.ts (k/ℓ-wide wrappers)

rounding.ts
  <- (Power2Round, Decompose, HighBits, LowBits, MakeHint, UseHint, HintBitPack/Unpack with §D.3 checks)

sampling.ts
  <- (rej_ntt_poly, rej_bounded_poly, SampleInBall, all consume SHAKE PRF output written into XOF_PRF_OFFSET by host)

encoding.ts
  <- (bit-pack/unpack at every required width: encodeS₁/encodeS₂, encodeT₀/encodeT₁, encodeZ, encodeSig)

index.ts
  re-exports: params + buffers + reduce + ntt + ntt_simd + poly + poly_simd + polyvec + rounding + sampling + encoding
```

**SLH-DSA (`src/asm/slhdsa/`)**

```
params.ts
  <- hashes.ts, wots.ts, fors.ts, xmss.ts, hypertree.ts, slh.ts (n / h / d / h' / a / k / lg_w per parameter set)

buffers.ts
  <- every other file (INPUT / OUT / STATE / SCRATCH offsets, ADRS_OFFSET, PARAMS_OFFSET)

keccak.ts
  <- hashes.ts (embedded SHAKE128 / SHAKE256 sponge state; verbatim port from src/asm/sha3/)

address.ts
  <- hashes.ts, wots.ts, fors.ts, xmss.ts, hypertree.ts (32-byte ADRS struct, BE-32 limbs, FIPS 205 §4.2)

hashes.ts
  <- wots.ts, fors.ts, xmss.ts, hypertree.ts, slh.ts (F / H / T_ℓ / PRF / PRF_msg / H_msg tweakable hash family, §11.2 SHAKE)

wots.ts
  <- xmss.ts (WOTS+ chains, §5)

fors.ts
  <- slh.ts (FORS authentication paths, §8)

xmss.ts
  <- hypertree.ts (XMSS subtrees, §6)

hypertree.ts
  <- slh.ts (hypertree composition, §7)

slh.ts
  <- index.ts (slhKeygenInternal / slhSignInternal / slhVerifyInternal, §9 Algorithms 18 / 19 / 20)

index.ts
  re-exports: buffers + params + address + hashes + wots + fors + xmss + hypertree + slh
```

**BLAKE3 (`src/asm/blake3/`)**

```
flags.ts
  <- compress.ts, chunk.ts, tree.ts (CHUNK_START / CHUNK_END / PARENT / ROOT / KEYED_HASH / DERIVE_KEY_* bits, §2.2 Table 3)

buffers.ts
  <- every other file (INPUT_STAGING / OUTPUT_STAGING / CV / MSG / COUNTER / FLAGS / LEVEL_QUEUES / ROOT_STATE_* offsets)

compress.ts
  <- chunk.ts, tree.ts (v128-internal single-block compress, §2.2)

compress_simd.ts
  <- chunk_simd.ts, tree_simd.ts (v128-external compress4 lane-parallel, §5.3)

chunk.ts
  <- tree.ts (§2.4 chunk machine with 1-block lookahead)

chunk_simd.ts
  <- tree.ts (compress4 chunk batching dispatch)

tree.ts
  <- index.ts (§2.5 tree assembly, queue-per-level, root finalize)

tree_simd.ts
  <- index.ts (compress4 parent dispatch, §5.3)

index.ts
  re-exports: buffers + flags + compress + compress_simd + chunk + chunk_simd + tree + tree_simd
  also exports _testChunkCV / _testParentCV / _testDeriveContextCV (gated for tree-internals tests and src/ts/merkle/blake3-tree.ts)
```

**Curve25519 (`src/asm/curve25519/`)**

```
buffers.ts
  <- every other file (FIELD_TMP / POINT_TMP / LADDER_TMP / ACC / SHA512_* / ED25519_* / X25519_* / BASEPOINT_U offsets)

field.ts
  <- edwards.ts, montgomery.ts, scalar.ts, compress.ts, ed25519.ts, x25519.ts (GF(2^255-19) radix-2^51 arithmetic, RFC 8032 §5.1)

scalar.ts
  <- ed25519.ts (scalar arithmetic mod L: clamp, reduce, mulAdd, canonical check)

edwards.ts
  <- compress.ts, ed25519.ts (edwards25519 in extended (X:Y:Z:T), point add / double, scalar mult)

montgomery.ts
  <- x25519.ts (X25519 Montgomery ladder over Curve25519 u-coord)

compress.ts
  <- ed25519.ts (point compression + strict-canonical decompression)

sha512.ts
  <- ed25519.ts (embedded SHA-512, verbatim port from src/asm/sha2/sha512.ts)

ed25519.ts
  <- index.ts (RFC 8032 sign / verify, pure + prehash, fault-injection cross-check)

x25519.ts
  <- index.ts (RFC 7748 keygen / DH against the basepoint u=9 and a peer pk)

index.ts
  re-exports: buffers + field + scalar + edwards + montgomery + compress + sha512 + ed25519 + x25519
```

**P-256 (`src/asm/p256/`)**

```
buffers.ts
  <- every other file (MUL_INT_* / FIELD_TMP / POINT_TMP / SCALAR_TMP / HMAC_DRBG_* / ECDSA_* / SHA256_* / HMAC256_* offsets)

field.ts
  <- scalar.ts, point.ts, scalar_mult.ts, ecdsa.ts (GF(p256) at 8 × u32 saturated radix-2^32, HMV §2.4.1 Algorithm 2.27 Solinas reduction)

scalar.ts
  <- point.ts, scalar_mult.ts, rfc6979.ts, ecdsa.ts (scalar arithmetic mod n via bit-by-bit binary division, FIPS 186-5 §6 BE wire form)

point.ts
  <- scalar_mult.ts, ecdsa.ts (projective (X:Y:Z) over short Weierstrass, Renes-Costello-Batina 2016 complete add / double specialised for a = -3)

scalar_mult.ts
  <- ecdsa.ts (constant-time double-and-add-always scalar multiplication, variable + fixed base)

sha256.ts
  <- hmac_sha256.ts, rfc6979.ts, ecdsa.ts (embedded SHA-256, verbatim port from src/asm/sha2/sha256.ts)

hmac_sha256.ts
  <- rfc6979.ts (embedded HMAC-SHA-256, verbatim port from src/asm/sha2/hmac.ts)

rfc6979.ts
  <- ecdsa.ts (RFC 6979 §3.2 deterministic + draft-irtf-cfrg-det-sigs-with-noise-05 §4 hedged HMAC-DRBG K-derivation)

ecdsa.ts
  <- index.ts (FIPS 186-5 §6.4 sign / §6.4.4 verify entry points, RFC 6979 §3.5 low-S enforcement)

index.ts
  re-exports: buffers + field + scalar + point + scalar_mult + sha256 + hmac_sha256 + rfc6979 + ecdsa
```

**Constant-time equality (`src/asm/cte/`)**

```
index.ts
  asc entry point. Exports compare(aOff, bOff, len): i32 only. Uses
  v128.xor / v128.or accumulator over 16-byte blocks with a scalar tail
  for the remainder. No staging buffers, no wipeBuffers export.

shared.ts
  Source-level export only, not compiled to its own WASM binary.
  Exports @inline ctEqual(aOff, bOff, len): i32. Scalar XOR-accumulate
  with branch-free reduction. Imported by kyber/verify.ts,
  slhdsa/hypertree.ts, curve25519/ed25519.ts, and p256/ecdsa.ts; the
  AS compiler inlines the body at each call site. Never emitted as a
  WASM export from any consumer binary.
```

---

## Cross-References

| Document | Description |
| -------- | ----------- |
| [index](./README.md) | Project Documentation index |
| [architecture](./architecture.md) | Repository structure, build and CI, WASM modules, public API, test suite, and security posture |
| [asm_cte.md](./asm_cte.md) | WASM implementation: SIMD constant-time byte equality backing `constantTimeEqual`, plus the `@inline` source-level `ctEqual` imported by other AS modules. Lazy-loaded, no `init()` |
| [asm_kyber.md](./asm_kyber.md) | WASM implementation: polynomial arithmetic, SIMD NTT/invNTT, basemul in Z_q[X]/(X²-ζ), CBD sampling, compression, FO transform |
| [asm_curve25519.md](./asm_curve25519.md) | WASM implementation: field arithmetic, edwards25519, Montgomery ladder, scalar mod L, embedded SHA-512 |
| [asm_p256.md](./asm_p256.md) | p256 WASM implementation: GF(p256) field arithmetic, Renes-Costello-Batina 2016 complete addition, constant-time scalar mult, embedded SHA-256 + HMAC-SHA-256 for RFC 6979 K derivation |
| [asm_mldsa.md](./asm_mldsa.md) | WASM implementation: SIMD NTT over q=8380417, rejection sampling, Power2Round / Decompose / MakeHint / UseHint, HintBitPack/Unpack with §D.3 SUF-CMA checks, SampleInBall |
| [asm_slhdsa.md](./asm_slhdsa.md) | WASM implementation: embedded Keccak permutation, F / H / T_ℓ / PRF / PRF_msg / H_msg tweakable hash family, 32-byte ADRS encoding, WOTS+ / FORS / XMSS / hypertree composition |
| [asm_aes.md](./asm_aes.md) | WASM implementation: bitsliced 8-block kernel, Canright tower-field S-box, CBC/CTR/GCM/GCM-SIV modes |
| [asm_serpent.md](./asm_serpent.md) | WASM implementation: bitslice S-boxes, key schedule, CTR/CBC modes |
| [asm_chacha.md](./asm_chacha.md) | WASM implementation: quarter-round, Poly1305 accumulator, HChaCha20 |
| [asm_sha2.md](./asm_sha2.md) | WASM implementation: compression functions, HMAC inner/outer padding |
| [asm_sha3.md](./asm_sha3.md) | WASM implementation: Keccak permutation (1600-bit state), sponge construction |
| [asm_blake3.md](./asm_blake3.md) | WASM implementation: v128-internal `compress` and lane-parallel `compress4` (BLAKE3 §5.3 SIMD), §2.4 chunk machine, §2.5 tree assembly + root finalize, §2.6 XOF squeeze, all three §2.3 modes |
