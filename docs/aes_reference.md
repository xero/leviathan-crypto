<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### AES Algorithm Reference

Algorithm specification, bitsliced AES-NI-free implementation details, and known attack analysis for AES-128/192/256 and the GCM and GCM-SIV AEAD modes shipped by this library. The headline configuration is **AES-256-GCM-SIV**: 14 rounds, nonce-misuse-resistant, 128-bit tag, with a per-nonce POLYVAL authentication key derived from the master key.

#### **Sources:**
- NIST FIPS 197 (Daemen & Rijmen, 2001; final update 2023),
- NIST SP 800-38A (Dworkin, 2001) for CBC and CTR,
- NIST SP 800-38D (Dworkin, 2007) for GCM and GHASH,
- RFC 8452 (Gueron, Langley, & Lindell, 2019) for AES-GCM-SIV and POLYVAL,
- Käsper & Schwabe, CHES 2009 (constant-time bitsliced AES-CTR/GCM),
- Canright, CHES 2005 (compact GF(2⁸) tower-field S-box),
- Boyar & Peralta, "A Small Depth-16 Circuit for the AES S-Box" (SEC 2012).

> ### Table of Contents
> - [Algorithm Overview](#algorithm-overview)
>   - [Origins and Design Goals](#origins-and-design-goals)
>   - [The AES Family](#the-aes-family)
>   - [From Block Cipher to AEAD](#from-block-cipher-to-aead)
>   - [AES vs Serpent vs ChaCha20](#aes-vs-serpent-vs-chacha20)
> - [Algorithm Specification](#algorithm-specification)
>   - [Parameters](#parameters)
>   - [Key Schedule](#key-schedule)
>   - [SubBytes](#subbytes)
>   - [ShiftRows](#shiftrows)
>   - [MixColumns](#mixcolumns)
>   - [AddRoundKey](#addroundkey)
>   - [Round Function](#round-function)
>   - [Encryption](#encryption)
>   - [Decryption](#decryption)
>   - [CBC and CTR](#cbc-and-ctr)
>   - [GCM](#gcm)
>   - [GCM-SIV](#gcm-siv)
> - [Design and Implementation](#design-and-implementation)
>   - [Bitsliced 8-Block Kernel](#bitsliced-8-block-kernel)
>   - [Tower-Field S-Box](#tower-field-s-box)
>   - [Boyar-Peralta 113-Gate Scalar S-Box](#boyar-peralta-113-gate-scalar-s-box)
>   - [Equivalent Inverse Cipher Decrypt Path](#equivalent-inverse-cipher-decrypt-path)
>   - [Three Counter Encodings](#three-counter-encodings)
>   - [Bitsliced vs Table-Driven vs AES-NI](#bitsliced-vs-table-driven-vs-aes-ni)
> - [Known Attacks](#known-attacks)
>   - [Differential and Linear Cryptanalysis](#differential-and-linear-cryptanalysis)
>   - [Biclique Cryptanalysis](#biclique-cryptanalysis)
>   - [Related-Key Attacks](#related-key-attacks)
>   - [T-Table Cache-Timing Attacks](#t-table-cache-timing-attacks)
>   - [GHASH Side-Channel and POLYVAL Mitigation](#ghash-side-channel-and-polyval-mitigation)
>   - [Nonce Misuse and Reuse](#nonce-misuse-and-reuse)
>   - [Forgery Bound](#forgery-bound)
>   - [Power Analysis and DPA](#power-analysis-and-dpa)
>   - [Overall Security Assessment](#overall-security-assessment)

---

## Algorithm Overview

### Origins and Design Goals

AES is the block cipher Rijndael, designed by Joan Daemen and Vincent Rijmen
(KU Leuven) and submitted to the NIST AES competition in 1998. NIST selected
Rijndael as the winner in October 2000 and standardised it as FIPS 197 in
November 2001. The 2023 final update (FIPS 197-upd1) is the current
authoritative text.

The designers' priorities were software speed across a wide range of
architectures, simplicity of implementation, and a small algebraic core. AES
uses a single 8-bit S-box derived from inversion in GF(2⁸) followed by an
affine transform. Diffusion comes from a fixed linear layer (ShiftRows +
MixColumns) chosen under the wide-trail strategy, which bounds the
probability of differential and linear trails by counting active S-boxes
across rounds rather than analysing them one round at a time.

Serpent, by Anderson, Biham, and Knudsen, placed second in the competition
on a more conservative 32-round design. NIST selected Rijndael partly for
its faster software performance and partly for hardware friendliness; both
ciphers had strong cryptanalytic margins.

### The AES Family

AES is one cipher with three key sizes. The block size is fixed at 128 bits
and the round function is identical across the family. The key size selects
the round count and the length of the key schedule.

| Variant | Key | Rounds (Nr) | Round keys (Nr+1) |
|---------|-----|-------------|-------------------|
| AES-128 | 128 bits | 10 | 11 |
| AES-192 | 192 bits | 12 | 13 |
| AES-256 | 256 bits | 14 | 15 |

All three variants share the same SubBytes table, the same ShiftRows
permutation, the same MixColumns matrix, and the same AddRoundKey step. The
key schedule differs only in expansion length and, for AES-256, an extra
SubWord application every eight expanded words (FIPS 197 §5.2).

### From Block Cipher to AEAD

A raw block cipher is not directly useful for encrypting a stream of data.
ECB mode reveals plaintext repetitions and is unsafe for any non-toy
purpose. CBC and CTR provide confidentiality only; both are vulnerable to
bit-flipping, chosen-ciphertext manipulation, and (for CBC) padding-oracle
attacks. Both must be paired with an authenticator such as HMAC under
Encrypt-then-MAC, or replaced with an authenticated mode.

GCM (NIST SP 800-38D) glues CTR-mode encryption to a polynomial MAC
(GHASH) over the field GF(2¹²⁸). It produces ciphertext, AAD coverage, and
a 128-bit authentication tag in a single pass. GCM is the dominant AEAD on
the modern internet, deployed in TLS 1.3, IPsec, SSH, and most disk and
filesystem encryption stacks.

GCM has one sharp edge: nonce reuse under the same key recovers the GHASH
authentication subkey H, which then enables universal forgery for every
past and future message under that key. RFC 8452 specifies AES-GCM-SIV, a
nonce-misuse-resistant variant that derives a fresh POLYVAL authentication
key and a fresh AES encryption key from the master key and the nonce on
every call. Under nonce reuse, AES-GCM-SIV leaks only whether two
encryptions had identical (nonce, AAD, plaintext) inputs; key recovery and
universal forgery are not enabled.

The library promotes **AES-256-GCM-SIV** as the recommended AES endpoint
and exposes it through both `AESGCMSIV` (the raw primitive) and the higher
level [`Seal` AEAD family](./aead.md) via `AESGCMSIVCipher`.

### AES vs Serpent vs ChaCha20

| Property | AES-256-GCM-SIV | Serpent-256 | XChaCha20-Poly1305 |
|----------|-----------------|-------------|---------------------|
| Block size | 128 bits | 128 bits | 512 bits (stream) |
| Key size | 256 bits | 256 bits | 256 bits |
| Rounds | 14 | 32 | 20 |
| S-box | One 8→8, GF(2⁸) inverse + affine | Eight 4→4, designed by criteria | None (ARX) |
| Algorithmic constant-time | No (GHASH/POLYVAL window) | Yes (bitsliced S-boxes) | Yes (ARX, no tables) |
| Nonce size | 96 bits | 128 bits | 192 bits |
| Tag size | 128 bits | 128 bits | 128 bits |
| Nonce-misuse posture | Resistant (SIV) | Resistant (Seal SIV construction) | Catastrophic on reuse |
| Best published attack on full cipher | Biclique, 2²⁵⁴·⁴ time | Biclique, 2²⁵⁵·²¹ time | None |

AES is the fastest of the three on hardware that exposes AES-NI or ARM
Cryptography Extensions. Without dedicated hardware, AES is the slowest of
the three and the only one with a residual cache-timing surface in this
library, located in the GHASH/POLYVAL multiplier rather than the cipher
itself. The [Known Attacks](#known-attacks) section is explicit about that
surface.

---

## Algorithm Specification

This section follows FIPS 197 for the AES core, SP 800-38A for CBC and
CTR, SP 800-38D for GCM, and RFC 8452 for AES-GCM-SIV. The library
implements AES-128, AES-192, and AES-256; pseudocode below describes
AES-256 (Nr = 14) with the variant differences called out where they
matter. The pseudocode budget is spent on the AES core, GCM, and GCM-SIV;
CBC and CTR are summarised briefly.

### Parameters

| Parameter | Value |
|-----------|-------|
| Block size | 128 bits |
| Key sizes | 128, 192, or 256 bits |
| Rounds (Nr) | 10, 12, or 14 |
| Round keys | Nr + 1, each 128 bits |
| S-box | One 8→8 substitution (FIPS 197 §5.1.1) |
| State | 4×4 matrix of bytes, column-major |
| Field | GF(2⁸) under irreducible polynomial m(x) = x⁸ + x⁴ + x³ + x + 1 (`0x11B`) |

The state is a 4×4 byte matrix loaded from the 128-bit input in column-major
order: input byte 0 fills state[0,0], byte 1 fills state[1,0], byte 4 fills
state[0,1], and so on (FIPS 197 §3.4).

### Key Schedule

The key schedule expands an Nk-word seed (Nk ∈ {4, 6, 8}) into 4·(Nr+1)
round-key words via a recurrence over `RotWord`, `SubWord`, and `Rcon`
(FIPS 197 §5.2):

```
Input:  K (Nk × 32 bits)
Output: w[0..4·(Nr+1)−1]

1. For i = 0 to Nk−1:
     w[i] = K[i]
2. For i = Nk to 4·(Nr+1)−1:
     temp = w[i−1]
     if  i mod Nk = 0:
         temp = SubWord(RotWord(temp)) ⊕ Rcon[i/Nk]
     elif Nk > 6 and i mod Nk = 4:
         temp = SubWord(temp)                          (AES-256 only)
     w[i] = w[i−Nk] ⊕ temp
```

Where:
- `RotWord` rotates a 4-byte word left by one byte: `(a,b,c,d) → (b,c,d,a)`.
- `SubWord` applies the AES S-box to each of the four bytes independently.
- `Rcon[j]` is `(x^(j−1), 0, 0, 0)` over GF(2⁸): the constants 0x01, 0x02,
  0x04, ..., 0x80, 0x1B, 0x36 for j = 1..10.

AES-256 alone applies the extra `SubWord` step every eight expanded words
(the `Nk > 6 and i mod Nk = 4` branch). This is the load-bearing
nonlinearity that distinguishes AES-256's schedule from AES-128 and
AES-192. The related-key analysis described in the [Known Attacks](#known-attacks)
section exploits gaps in this nonlinearity, not its presence.

The 128-bit round keys are formed by concatenating four consecutive words:
RoundKey_r = w[4r] ‖ w[4r+1] ‖ w[4r+2] ‖ w[4r+3].

### SubBytes

SubBytes replaces each byte `a` of the state by `S(a) = A · a⁻¹ ⊕ b`, where
`a⁻¹` is the multiplicative inverse in GF(2⁸) under the irreducible
polynomial `0x11B` (with the convention that `0⁻¹ = 0`), `A` is a fixed
8×8 invertible matrix over GF(2), and `b` is the constant `0x63` (FIPS 197
§5.1.1). The forward S-box is:

```
     0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
00: 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76
10: ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0
20: b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15
30: 04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75
40: 09 83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84
50: 53 d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf
60: d0 ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8
70: 51 a3 40 8f 92 9d 38 f5 bc b6 da 21 10 ff f3 d2
80: cd 0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73
90: 60 81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db
a0: e0 32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79
b0: e7 c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08
c0: ba 78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a
d0: 70 3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e
e0: e1 f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df
f0: 8c a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16
```

Read as `S[row, col]`: `S[0x00] = 0x63`, `S[0x53] = 0xed`, `S[0xff] = 0x16`.

The inverse S-box (used during decryption) inverts the affine first, then
the GF(2⁸) inversion. The inverse pre-affine constant is `0x7E`:

```
     0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
00: 52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb
10: 7c e3 39 82 9b 2f ff 87 34 8e 43 44 c4 de e9 cb
20: 54 7b 94 32 a6 c2 23 3d ee 4c 95 0b 42 fa c3 4e
30: 08 2e a1 66 28 d9 24 b2 76 5b a2 49 6d 8b d1 25
40: 72 f8 f6 64 86 68 98 16 d4 a4 5c cc 5d 65 b6 92
50: 6c 70 48 50 fd ed b9 da 5e 15 46 57 a7 8d 9d 84
60: 90 d8 ab 00 8c bc d3 0a f7 e4 58 05 b8 b3 45 06
70: d0 2c 1e 8f ca 3f 0f 02 c1 af bd 03 01 13 8a 6b
80: 3a 91 11 41 4f 67 dc ea 97 f2 cf ce f0 b4 e6 73
90: 96 ac 74 22 e7 ad 35 85 e2 f9 37 e8 1c 75 df 6e
a0: 47 f1 1a 71 1d 29 c5 89 6f b7 62 0e aa 18 be 1b
b0: fc 56 3e 4b c6 d2 79 20 9a db c0 fe 78 cd 5a f4
c0: 1f dd a8 33 88 07 c7 31 b1 12 10 59 27 80 ec 5f
d0: 60 51 7f a9 19 b5 4a 0d 2d e5 7a 9f 93 c9 9c ef
e0: a0 e0 3b 4d ae 2a f5 b0 c8 eb bb 3c 83 53 99 61
f0: 17 2b 04 7e ba 77 d6 26 e1 69 14 63 55 21 0c 7d
```

The library does not store these tables. Both forward and inverse S-boxes
are computed on the fly as Boolean circuits; see the [Design and
Implementation](#design-and-implementation) section.

### ShiftRows

ShiftRows cyclically rotates the rows of the state to the left by 0, 1, 2,
and 3 byte positions for rows 0, 1, 2, and 3 respectively (FIPS 197 §5.1.2).
The transform is fixed and key-independent.

```
Before:                           After:
[s00 s01 s02 s03]                 [s00 s01 s02 s03]
[s10 s11 s12 s13]   ShiftRows →   [s11 s12 s13 s10]
[s20 s21 s22 s23]                 [s22 s23 s20 s21]
[s30 s31 s32 s33]                 [s33 s30 s31 s32]
```

InvShiftRows rotates right by the same amounts.

### MixColumns

MixColumns multiplies each column of the state, treated as a polynomial
over GF(2⁸), by the fixed polynomial `a(x) = {03}x³ + {01}x² + {01}x +
{02}` modulo `x⁴ + 1` (FIPS 197 §5.1.3). In matrix form:

```
[ s'_0 ]   [ 02 03 01 01 ] [ s_0 ]
[ s'_1 ] = [ 01 02 03 01 ] [ s_1 ]
[ s'_2 ]   [ 01 01 02 03 ] [ s_2 ]
[ s'_3 ]   [ 03 01 01 02 ] [ s_3 ]
```

InvMixColumns multiplies by the inverse polynomial with coefficients
`{0E, 09, 0D, 0B}`. The matrix is the inverse of the forward matrix over
GF(2⁸).

### AddRoundKey

AddRoundKey XORs the 128-bit round key into the state byte by byte (FIPS
197 §5.1.4). It is its own inverse.

### Round Function

Each round of AES-256 (rounds 1 through 13) applies four operations in
order:

1. **SubBytes:** apply the S-box to each byte of the state.
2. **ShiftRows:** cyclically shift the four rows.
3. **MixColumns:** multiply each column by the fixed matrix.
4. **AddRoundKey:** XOR the round key.

Round 0 is a single AddRoundKey before the first SubBytes. Round 14 (the
final round) drops MixColumns:

1. **SubBytes**
2. **ShiftRows**
3. **AddRoundKey** (with the last round key)

Omitting MixColumns from the final round and replacing it with AddRoundKey
makes encryption and decryption mirror images of each other under the
Equivalent Inverse Cipher construction; see the [Design and
Implementation](#design-and-implementation) section.

### Encryption

```
Input:  128-bit plaintext P, key K (128/192/256 bits)
Output: 128-bit ciphertext C

1. Derive round keys w[0..4·(Nr+1)−1] from K via the key schedule
2. state = P
3. AddRoundKey(state, RoundKey_0)
4. For r = 1 to Nr−1:
     SubBytes(state)
     ShiftRows(state)
     MixColumns(state)
     AddRoundKey(state, RoundKey_r)
5. SubBytes(state)
   ShiftRows(state)
   AddRoundKey(state, RoundKey_Nr)
6. C = state
```

Nr is 10 for AES-128, 12 for AES-192, 14 for AES-256.

### Decryption

The library uses the FIPS 197 §5.3.5 Equivalent Inverse Cipher decrypt
form, in which the round loop mirrors encrypt. Round keys 1 through Nr−1
have InvMixColumns pre-applied at key-schedule time so AddRoundKey reuses
the existing structure.

```
Input:  128-bit ciphertext C, key K (128/192/256 bits)
Output: 128-bit plaintext P

1. Derive round keys w[0..4·(Nr+1)−1] from K via the key schedule
2. For r = 1 to Nr−1: dw[r] = InvMixColumns(w[r])
3. state = C
4. AddRoundKey(state, RoundKey_Nr)
5. For r = Nr−1 down to 1:
     InvSubBytes(state)
     InvShiftRows(state)
     InvMixColumns(state)
     AddRoundKey(state, dw[r])
6. InvSubBytes(state)
   InvShiftRows(state)
   AddRoundKey(state, RoundKey_0)
7. P = state
```

The straightforward decrypt form (FIPS 197 §5.3) interleaves InvShiftRows
before InvSubBytes and applies InvMixColumns to the state rather than the
key. Both forms produce identical output; the Equivalent Inverse Cipher is
preferred here because it reuses the encrypt round structure and shares
the SubBytes circuit between encrypt and decrypt paths.

### CBC and CTR

The library exposes raw `AESCbc` and `AESCtr` primitives for callers who
need them, but neither mode authenticates ciphertext on its own.

`AESCbc` implements CBC mode with PKCS7 padding (SP 800-38A §6.2; RFC
5652 §6.3). The constructor requires `{ dangerUnauthenticated: true }`
opt-in and the decrypt path performs branch-free PKCS7 validation,
returning a single generic `RangeError('invalid ciphertext')` for every
failure mode. This closes the Vaudenay-2002 padding-oracle surface but
does not authenticate the ciphertext. Pair with HMAC-SHA-256 under
Encrypt-then-MAC, verify the tag with `constantTimeEqual`, and only then
call `decrypt`.

`AESCtr` implements CTR mode with a 128-bit big-endian counter (SP
800-38A §6.5, Appendix B.1). Encrypt and decrypt are the same operation:
the counter advances across calls until the user resets the nonce.
Confidentiality only; pair with a MAC.

For all production traffic the library recommends `AESGCM`, `AESGCMSIV`,
or the [`Seal` AEAD family](./aead.md) over raw CBC or CTR.

### GCM

AES-GCM (SP 800-38D) combines AES-CTR keystream with GHASH over GF(2¹²⁸)
to produce an authenticated ciphertext.

GHASH operates on 128-bit blocks under the irreducible polynomial
x¹²⁸ + x⁷ + x² + x + 1, with the bit ordering specified in SP 800-38D
§6.3 (the most-significant bit of byte 0 is the constant-term coefficient
u⁰). The hash subkey H is `AES_K(0¹²⁸)`. The AAD is padded to a 16-byte
boundary, the ciphertext is padded to a 16-byte boundary, and a final
block encodes `len(AAD)` and `len(C)` as 64-bit big-endian integers:

```
GHASH_H(AAD, C) = GHASH over:
    pad16(AAD) ‖ pad16(C) ‖ len(AAD)₆₄ ‖ len(C)₆₄
```

The pre-counter J0 depends on the nonce length:

- 96-bit nonce (the recommended case): `J0 = nonce ‖ 0³¹ ‖ 1`.
- Any other length: `J0 = GHASH_H(0ᵏ ‖ pad16(nonce) ‖ 0⁶⁴ ‖ len(nonce)₆₄)`.

Encryption applies CTR-mode keystream starting at `inc_32(J0)` and
finishes with the tag:

```
Input:  K (16/24/32 bytes), IV (any non-empty length), P, A
Output: ciphertext C, tag T (128 bits)

1. H = AES_K(0¹²⁸)
2. J0 = nonce-derived pre-counter (96-bit case or GHASH case as above)
3. C = GCTR_K(inc_32(J0), P)
4. S = GHASH_H( pad16(A) ‖ pad16(C) ‖ len(A)₆₄ ‖ len(C)₆₄ )
5. T = MSB_128( AES_K(J0) ⊕ S )                            // tag
```

`inc_32` increments the rightmost 32 bits of the 128-bit counter as a
big-endian integer modulo 2³²; the leftmost 96 bits are fixed across the
operation (SP 800-38D §6.5). Decryption verifies T before returning P:

```
Input:  K, IV, C, A, T
Output: P, or authentication failure

1. H, J0 as above
2. S = GHASH_H( pad16(A) ‖ pad16(C) ‖ len(A)₆₄ ‖ len(C)₆₄ )
3. T' = MSB_128( AES_K(J0) ⊕ S )
4. If T ≠ T' (constant-time compare): FAIL
5. P = GCTR_K(inc_32(J0), C)
```

The library `AESGCM` class is single-shot and supports AES-128/192/256
with a 128-bit tag. Plaintext is bounded by SP 800-38D §5.2.1.1 at
`16 · (2³² − 2)` bytes; AAD and IV are bounded by the dedicated buffers
at 64 KiB each.

### GCM-SIV

AES-GCM-SIV (RFC 8452) is nonce-misuse-resistant authenticated AEAD over
AES-128 or AES-256. The library does not support AES-192-GCM-SIV; RFC 8452
§6 fixes K_LEN ∈ {16, 32}, and the constructor rejects 24-byte keys.

The construction differs from GCM in three load-bearing ways:

- **Per-nonce key derivation.** The master key (the key-generating key, KGK)
  is never used directly to authenticate or encrypt. A fresh authentication
  key and a fresh encryption key are derived from KGK and the 12-byte
  nonce per call.
- **POLYVAL universal hash.** GCM-SIV uses POLYVAL (RFC 8452 §3) instead
  of GHASH. POLYVAL is GHASH with reversed bit ordering and a different
  reduction polynomial (x¹²⁸ + x¹²⁷ + x¹²⁶ + x¹²¹ + 1), chosen so that the
  natural little-endian byte order of x86 is the natural field order.
- **SIV-CTR with the tag as initial counter.** Encryption uses AES-CTR
  with the authentication tag itself as the initial counter (with the
  most-significant bit of the last byte forced to 1 to separate the tag
  domain from the CTR domain). The counter increment is a 32-bit
  little-endian counter at bytes 0..3; bytes 4..15 are fixed across the
  call (RFC 8452 §4).

Per-nonce key derivation runs AES under KGK over a counter prefixed to the
nonce:

```
Input:  KGK, nonce N (12 bytes)
Output: auth_key (16 bytes), enc_key (16 or 32 bytes)

For ctr = 0 to 5:
    block[0..4]  = u32_le(ctr)
    block[4..16] = N
    out[ctr]     = AES_KGK(block)

auth_key = out[0][0..8] ‖ out[1][0..8]                  (16 bytes)
enc_key  = out[2][0..8] ‖ out[3][0..8]                  (AES-128: 16)
         ‖ out[4][0..8] ‖ out[5][0..8]                  (AES-256: 32)
```

Sealing:

```
Input:  KGK, nonce N (12B), plaintext P, AAD A
Output: ciphertext C, tag T (128 bits)

1. (auth_key, enc_key) = derive_keys(KGK, N)
2. S = POLYVAL(auth_key, pad16(A) ‖ pad16(P) ‖ le64(8·|A|) ‖ le64(8·|P|))
3. T_in = S ⊕ (N ‖ 0³²)            // XOR nonce into low 12 bytes
   T_in[15] &= 0x7F                 // clear MSB of last byte
4. T = AES_enc_key(T_in)            // 128-bit tag
5. IC = T ; IC[15] |= 0x80          // initial counter: tag with MSB forced
6. C = AES-CTR_enc_key(IC, P)        // 32-bit LE counter at bytes 0..3
```

Opening verifies the tag after decrypting plaintext (SIV is verify-after-
decrypt because the tag depends on the plaintext):

```
Input:  KGK, N, C, A, T
Output: P, or authentication failure

1. (auth_key, enc_key) = derive_keys(KGK, N)
2. IC = T ; IC[15] |= 0x80
3. P = AES-CTR_enc_key(IC, C)
4. S = POLYVAL(auth_key, pad16(A) ‖ pad16(P) ‖ le64(8·|A|) ‖ le64(8·|P|))
5. T_in = S ⊕ (N ‖ 0³²) ; T_in[15] &= 0x7F
6. T' = AES_enc_key(T_in)
7. If T ≠ T' (constant-time compare): wipe P and FAIL
8. Return P
```

The library `AESGCMSIV` class is single-shot, processes plaintext up to
64 KiB per call, accepts a 12-byte nonce, and produces a 16-byte tag.
The verify-after-decrypt path wipes the staged plaintext at
`CHUNK_PT_OFFSET` before throwing on tag mismatch, so unauthenticated
plaintext never becomes reachable from JavaScript.

> [!IMPORTANT]
> RFC 8452 §6 limits AES-GCM-SIV to roughly 2³² messages per master key.
> The bound comes from the per-nonce key-derivation function, not from
> the underlying AES or POLYVAL. Applications encrypting more than this
> under one key must rotate the master key.

---

## Design and Implementation

This section covers the design choices behind the WASM AES module. The
authoritative source-level reference is [`asm_aes.md`](./asm_aes.md); the
goal here is to explain *why* each choice was made.

### Bitsliced 8-Block Kernel

A naive AES implementation processes one block at a time and reads the
S-box from a 256-byte table indexed by secret state, which exposes a
cache-timing channel (see [T-Table Cache-Timing
Attacks](#t-table-cache-timing-attacks)). The library avoids tables
entirely by bitslicing the cipher across 8 parallel blocks using WASM
v128 SIMD lanes (Käsper & Schwabe, CHES 2009 §4.1, §4.3, §4.4).

Under the bitsliced representation, one v128 register holds bit `k` from
every byte across all 8 parallel blocks. The 128 byte positions of an AES
state become 128 v128 registers (8 bits per byte × 16 bytes); each
register carries one bit-position-per-block from all 8 blocks
simultaneously. SubBytes, ShiftRows, MixColumns, and AddRoundKey all
become register-only Boolean circuits with no data-dependent memory
access. The kernel is constant-time at the gate level.

The 8-block batch matches the natural granularity of the v128 lane: 8
blocks × 16 bytes / 16 lanes per v128 = exactly one byte per lane per
block. Larger batches (16, 32) need wider SIMD; smaller batches waste
lanes. CTR mode and CBC decrypt use the 8-block kernel directly; CBC
encrypt is sequential by definition and uses a scalar path.

### Tower-Field S-Box

The bitsliced S-box circuit is Canright's GF(2⁸) tower-field
decomposition (Canright, CHES 2005). Inversion in GF(2⁸) is computed
through GF((2⁴)²) over GF((2²)²), reducing the problem to short circuits
over GF(2²) and GF(2⁴) that compose cleanly into Boolean gates over the
v128 lanes.

The forward affine constant is `0x63` and the inverse pre-affine constant
is `0x7E` (equivalent to `0x05` after the bit-reversal that the
decomposition imposes on the circuit). The construction has no S-box
lookup tables anywhere; the gate-only circuit is constant-time by
construction.

### Boyar-Peralta 113-Gate Scalar S-Box

Bitslicing 8 blocks is excellent for bulk encryption but wasteful for the
4-byte `SubWord` step inside the key schedule. Expanding a key schedule
via the bitsliced kernel would mean filling 7 lanes with garbage to
encrypt a single 4-byte slice, then discarding most of the output.

The library uses a separate scalar S-box for `SubWord`: the Boyar-Peralta
straight-line program (32 AND gates, 81 XOR/XNOR gates, depth 27). This
is the smallest known gate-count circuit for the AES S-box that does not
require GF(2⁸) inversion through tower-field decomposition. It is faster
than the bitsliced kernel for single-byte calls and produces the same
output byte for byte.

The dual implementation is a deliberate split:

- **Bulk encrypt/decrypt** uses the bitsliced 8-block kernel for
  throughput.
- **Key schedule** uses Boyar-Peralta scalar `sboxByte` and `sboxWord`
  for latency.

Both circuits are constant-time at the gate level. Both produce identical
S-box output. The split is purely a performance optimisation.

### Equivalent Inverse Cipher Decrypt Path

FIPS 197 §5.3.5 specifies an alternative decrypt formulation in which the
round loop mirrors encrypt rather than running encrypt's steps in
reverse. The Equivalent Inverse Cipher (EIC) requires that round keys 1
through Nr−1 are pre-transformed by InvMixColumns at key-schedule time
so AddRoundKey reuses the existing structure.

The library uses EIC for decrypt:

- `loadKey` derives the forward round keys for encrypt and the
  InvMixColumns-transformed round keys for decrypt, both at key-schedule
  time.
- `decryptBlock` and `decryptBlock_8x` reuse the encrypt round skeleton
  (SubBytes/ShiftRows/MixColumns/AddRoundKey) substituting the inverse
  primitives (InvSubBytes/InvShiftRows/InvMixColumns) and reading from
  the inverse round-key buffer.

This shares more code between encrypt and decrypt paths than the
straightforward decrypt form (FIPS 197 §5.3) and matches the structure
used by AES-NI and ARM Cryptography Extensions, which is the same
EIC-compatible round shape.

### Three Counter Encodings

The library implements three counter modes on top of the shared AES
kernel. Each owns its own counter loop because the encodings differ in
endianness, width, and which bytes the increment touches.

**Standalone CTR (SP 800-38A §F.5).** A 128-bit big-endian counter. Byte
15 is the least-significant byte; carry propagates from byte 15 toward
byte 0. The full 128-bit width never wraps in practice because the
counter exhausts long before reaching 2¹²⁸.

**GCM (SP 800-38D §6.5).** A 128-bit block whose leftmost 96 bits are
fixed by J0 and whose rightmost 32 bits are a big-endian counter that
increments per block (`inc_32`). The fixed prefix is the nonce in the
recommended 96-bit case; for any other nonce length, J0 is derived via a
GHASH call. The 32-bit counter wraps mod 2³² silently, which limits a
single GCM operation to 16 · (2³² − 2) bytes of plaintext (SP 800-38D
§5.2.1.1).

**GCM-SIV (RFC 8452 §4).** A 128-bit block whose bytes 0..3 hold a
32-bit little-endian counter and whose bytes 4..15 are fixed across the
call. The initial value is the authentication tag with the
most-significant bit of byte 15 forced to 1 (so the CTR domain cannot
collide with the tag domain). The counter wraps mod 2³² silently, which
limits a single SIV operation to roughly 64 GiB of plaintext; the
library further bounds plaintext to 64 KiB per call as a single-shot
single-allocation API.

The three modes share the AES kernel but each owns its own counter
buffer and increment logic. This rules out a class of subtle bugs in
which a counter encoded for one mode is accidentally fed to another.

### Bitsliced vs Table-Driven vs AES-NI

| Property | Bitsliced (this library) | T-table software | AES-NI / ARMv8 |
|----------|--------------------------|------------------|-----------------|
| S-box implementation | Boolean circuit on v128 lanes | 4 KB lookup tables indexed by secret | Single-instruction `AESENC` round |
| Cache-timing in S-box | None | Yes, on shared cache | None |
| Key-schedule S-box | Boyar-Peralta scalar circuit | Same 256-byte table | `AESKEYGENASSIST` |
| Throughput, bulk | High (8 blocks per kernel call) | Medium | Highest |
| Throughput, single block | Lower (transpose overhead) | Medium | Highest |
| Hardware required | WASM v128 SIMD | None | AES-NI / ARMv8 Crypto |
| Target environment | Browsers, Node, Workers, edge | Legacy embedded | x86-64, ARMv8 server |
| GHASH/POLYVAL surface | Yes, 4-bit windowed table | Yes, same approach | None (`PCLMULQDQ`) |

The library targets WASM. AES-NI is not exposed to WebAssembly today and
neither is `PCLMULQDQ`; a fully table-free GHASH/POLYVAL multiplier in
WASM is too slow for production. The bitsliced kernel removes the
T-table cache-timing surface entirely. The remaining algorithmic-layer
side-channel surface is the GHASH/POLYVAL multiplier, addressed below.

---

## Known Attacks

AES-256-GCM-SIV: industry standard, sharpened. 14 rounds bitsliced into
Boolean gates with tower-field S-box with no table lookups. A fresh
POLYVAL key per nonce leaves GHASH-key recovery with no target.

> [!CAUTION]
> AES is **not** constant-time at the algorithm level the way Serpent
> (bitslice) and XChaCha20 (ARX) are. The residual leak in this library
> is the GHASH multiplier inside `AESGCM` and the POLYVAL backend in
> `AESGCMSIV`. Both use a 256-byte 4-bit-windowed multiplication table
> indexed by secret-derived state. This matches the posture of
> BoringSSL, OpenSSL, and RustCrypto on hardware without `PCLMULQDQ`:
> WebAssembly does not currently expose carry-less multiply, so a fully
> table-free GHASH or POLYVAL is not implementable in this environment
> without unacceptable throughput cost. The library documents the leak
> surface, mitigates it by deriving the POLYVAL authentication key per
> nonce from the master key in `AESGCMSIV` rather than fixing it across
> the session, and recommends the [`Seal` AEAD family](./aead.md) over
> the lower-level `AESGCM` primitive.

### Differential and Linear Cryptanalysis

**Source:** Daemen & Rijmen, *The Design of Rijndael* (Springer, 2002),
Ch. 9.
**Rounds reached:** 4 (trail bound)
**Type:** Wide-trail strategy bounds on differential and linear trails.

The wide-trail strategy bounds the number of active S-boxes across any
4-round trail at 25, given the AES MixColumns branch number of 5. The
maximum differential probability per S-box is 2⁻⁶ and the maximum
absolute linear bias per S-box is 2⁻³, giving:

- 4-round differential trail probability ≤ 2⁻¹⁵⁰
- 4-round linear trail bias ≤ 2⁻⁷⁵

These are *trail* bounds, not differential or hull bounds; the actual
distinguisher complexity is at least these large. AES-256 has 14
rounds, leaving substantial margin. No published differential or linear
distinguisher reaches more than a small number of rounds beyond the
trail bound.

**Practical threat to full AES-256:** None.

### Biclique Cryptanalysis

**Source:** Bogdanov, Khovratovich, & Rechberger, "Biclique Cryptanalysis
of the Full AES" (ASIACRYPT 2011).
**Rounds reached:** 14 (full)
**Type:** Biclique meet-in-the-middle on the full cipher.

Biclique cryptanalysis is the only published attack on full AES-256
that runs in less time than exhaustive key search. The attack
partitions the cipher into two parts and uses a biclique structure
across a few rounds at one end to amortise key-search cost.

| Variant | Rounds | Time | Data | Memory |
|---------|--------|------|------|--------|
| AES-128 | 10 | 2¹²⁶·¹ | 2⁸⁸ CP | ~2⁸ |
| AES-192 | 12 | 2¹⁸⁹·⁷ | 2⁸⁰ CP | ~2⁸ |
| AES-256 | 14 | 2²⁵⁴·⁴ | 2⁴⁰ CP | ~2⁸ |

The AES-256 result is roughly a factor of 4 faster than brute force.
The data complexity (2⁴⁰ chosen plaintexts under a single key) is
already at the edge of physical feasibility, the time complexity (2²⁵⁴)
is still effectively infeasible, and the speedup over exhaustive search
is cryptographically negligible.

**Practical threat to full AES-256:** None.

### Related-Key Attacks

**Source:** Biryukov & Khovratovich, "Related-Key Cryptanalysis of the
Full AES-192 and AES-256" (ASIACRYPT 2009).
**Rounds reached:** 14 (full, related-key model)
**Type:** Related-key boomerang on full AES-256.

The attack runs in 2⁹⁹·⁵ time and 2⁹⁹·⁵ data under 4 related keys with
chosen related-key differences (memory 2⁷⁷). It exploits the relative
simplicity of the AES-256 key schedule at the high-level structure.

The model assumption (an attacker chooses key relationships and obtains
encryptions under all of them) does not hold in real protocols. Modern
deployments derive AES keys via independent KDF outputs from a master
secret, not via attacker-chosen XOR relationships. The result is
significant for the academic understanding of the AES-256 key
schedule's margin and irrelevant to AEAD use under independent keys.

**Practical threat to AEAD use of AES-256:** None.

### T-Table Cache-Timing Attacks

**Source:** Bernstein, "Cache-timing attacks on AES" (2005); Osvik,
Shamir, & Tromer, "Cache Attacks and Countermeasures: The Case of AES"
(CT-RSA 2006); Bonneau & Mironov, "Cache-Collision Timing Attacks
Against AES" (CHES 2006); Tromer, Osvik, & Shamir, "Efficient Cache
Attacks on AES, and Countermeasures" (J. Cryptology, 2010).
**Rounds reached:** Implementation, not algorithm.
**Type:** Cache-line timing observations on table-driven AES.

The classic vulnerability of software AES: a T-table (or even a
single S-box table) implementation indexes a memory location at every
round based on plaintext XOR key. On any platform with a shared cache,
an attacker who can measure access time or share the cache observes
which cache lines a victim AES operation touches and recovers the key.

The library's bitsliced kernel removes this surface entirely. There are
no AES tables in linear memory at runtime; there are no key-dependent
memory accesses inside SubBytes, ShiftRows, MixColumns, or AddRoundKey.
The Boyar-Peralta scalar S-box used in the key schedule is also a
gate-only circuit with no table lookups.

**Practical threat under this library:** Removed at the AES layer.

### GHASH Side-Channel and POLYVAL Mitigation

**Source:** Procter & Cid, "On Weak Keys and Forgery Attacks Against
Polynomial-Based MAC Schemes" (FSE 2013); Saarinen, "Cycling Attacks on
GCM, GHASH and Other Polynomial MACs and Hashes" (FSE 2012); Gueron &
Lindell, "GCM-SIV: Full Nonce Misuse-Resistant Authenticated Encryption
at Under One Cycle per Byte" (CCS 2015); RFC 8452 (Gueron, Langley, &
Lindell, 2019).
**Type:** Cache-timing side channel and weak-key forgery against
polynomial MACs.

GHASH and POLYVAL multiply blocks by a hash subkey H in GF(2¹²⁸). A
table-free implementation of this multiplication is too slow without
hardware carry-less multiply (`PCLMULQDQ` on x86-64, `PMULL` on ARMv8).
The library uses a 256-byte 4-bit-windowed multiplication table indexed
by nibbles of the running state, precomputed once per call. The
resulting cache-timing surface is identical to the BoringSSL, OpenSSL,
and RustCrypto pre-`PCLMULQDQ` software paths.

Two mitigations exist in the library beyond what the underlying
algorithm provides:

- **GCM-SIV per-nonce key derivation.** Under `AESGCM`, the GHASH
  authentication subkey H is fixed across the entire session under one
  key. Recovery of H, including via cache observation across many
  encryptions, breaks authentication for every past and future message
  under that key. Under `AESGCMSIV`, the POLYVAL authentication key is
  derived per nonce from the master key (RFC 8452 §4); recovering the
  key for one message reveals nothing about any other message.
- **Seal AEAD recommended.** The [`Seal` AEAD family](./aead.md) wraps
  `AESGCMSIVCipher` (and `SerpentCipher`, and `XChaCha20Cipher`) in a
  uniform interface that handles nonce generation, key derivation, and
  framing. Most callers should use `Seal` rather than the lower-level
  `AESGCM` primitive.

The Procter-Cid analysis shows that any subset of GF(2¹²⁸) closed under
GHASH's multiplication structure forms a weak-key class, and forgery
succeeds with probability proportional to `|S|/2¹²⁸` if H lands in the
class. The practical impact on a 128-bit tag is small per key; the
analysis motivates GCM-SIV's H-derivation-per-nonce design more than
it threatens GCM directly.

**Practical threat to `AESGCMSIV` under this library:** Reduced to
per-message scope by per-nonce key derivation.

### Nonce Misuse and Reuse

Nonce reuse under GCM is catastrophic. Two messages encrypted under
the same (key, nonce) leak the keystream XOR to anyone who collects
both ciphertexts, and worse, the attacker recovers the GHASH
authentication subkey H. With H, the attacker forges valid tags for
every past and future message under the affected key.

Nonce reuse under GCM-SIV is graceful by design. The MRAE security
notion (Rogaway & Shrimpton, EUROCRYPT 2006) holds: under nonce reuse,
the attacker learns only whether two encryptions had identical (nonce,
AAD, plaintext) inputs. Key recovery, plaintext recovery beyond
equality, and universal forgery are not enabled. This is the formal
result Gueron & Lindell prove for GCM-SIV (CCS 2015) and that RFC 8452
codifies.

| Mode | Random 96-bit nonce | First reuse outcome | Second reuse outcome |
|------|---------------------|---------------------|----------------------|
| `AESGCM` | 50% collision near 2⁴⁸ messages | Keystream reuse | H recoverable; universal forgery |
| `AESGCMSIV` | 50% collision near 2⁴⁸ messages | Equality leak only | Equality leak only |

NIST SP 800-38D §8.3 limits random-nonce GCM use to 2³² invocations per
key to keep collision probability below 2⁻³². Applications that cannot
guarantee nonce uniqueness should use `AESGCMSIV` or `XChaCha20Cipher`
through `Seal`.

### Forgery Bound

**Source:** McGrew & Viega, "The Security and Performance of the
Galois/Counter Mode (GCM) of Operation" (INDOCRYPT 2004); Iwata, Ohashi,
& Minematsu, "Breaking and Repairing GCM Security Proofs" (CRYPTO 2012).

The forgery probability for AES-GCM with a 128-bit tag against a single
forgery attempt on a message of L 16-byte blocks is bounded by:

```
P_forgery ≤ (L + 1) / 2¹²⁸
```

For q forgery attempts: `q · (L + 1) / 2¹²⁸`. The bound applies block by
block; longer messages widen the forgery target marginally.

| Message size | Blocks (L) | Forgery probability (single attempt) |
|--------------|-----------:|--------------------------------------|
| 64 bytes     |          4 | 5 / 2¹²⁸ ≈ 2⁻¹²⁵·⁷                   |
| 1 KiB        |         64 | 65 / 2¹²⁸ ≈ 2⁻¹²¹·⁹                  |
| 64 KiB       |      4 096 | 4 097 / 2¹²⁸ ≈ 2⁻¹¹⁵·⁹                |
| 1 MiB        |     65 536 | 65 537 / 2¹²⁸ ≈ 2⁻¹¹¹·⁹               |

`AESGCMSIV` matches GCM's 128-bit tag forgery bound under unique nonces
and degrades gracefully under nonce reuse per Gueron-Lindell 2017. The
library's 64 KiB plaintext cap on `AESGCMSIV` keeps the per-call
forgery probability above 2⁻¹¹⁵, well below any practical threshold.

### Power Analysis and DPA

**Applicability:** Implementation-dependent.

Differential Power Analysis (DPA) attacks observe power consumption or
electromagnetic emissions during encryption to recover key bits. The
library's bitsliced kernel mixes every key bit into every register on
every round, providing fast key avalanche that complicates DPA
correlation.

Genuine DPA mitigation requires hardware countermeasures (masking,
shuffling, randomised execution order) outside the algorithm's scope.
WASM running inside a browser tab does not provide a DPA-relevant
threat model in the first place; physical access to the device is
already game over for the surrounding system.

### Overall Security Assessment

AES-256-GCM-SIV through this library has the following security posture
as of 2026:

| Attack class | Best result | Threat level |
|--------------|-------------|--------------|
| Differential (single-key) | Trail-bounded; no full-round distinguisher | None |
| Linear (single-key) | Trail-bounded; no full-round distinguisher | None |
| Biclique (single-key) | Full AES-256 in 2²⁵⁴·⁴ | None |
| Related-key | Full AES-256 in 2⁹⁹·⁵ under chosen related keys | None for AEAD use |
| T-table cache-timing | Removed by bitsliced kernel | None at AES layer |
| GHASH / POLYVAL cache-timing | 4-bit windowed table indexed by secret | Reduced per-message in GCM-SIV |
| Nonce reuse (`AESGCM`) | Universal forgery on second reuse | High; use `AESGCMSIV` |
| Nonce reuse (`AESGCMSIV`) | Equality leak only | None for confidentiality |
| Forgery (128-bit tag) | (L+1)/2¹²⁸ per attempt | None at practical L |
| Power analysis (DPA) | Implementation-dependent | Out of WASM threat model |

**Security margin.** The best mathematical attack on full AES-256 in
the single-key model is biclique cryptanalysis at 2²⁵⁴·⁴ time, roughly
0.6 bits below brute force. AES-GCM-SIV closes the residual nonce-misuse
and per-session-H exposure modes that affect AES-GCM. The bitsliced
kernel removes the T-table cache-timing surface that affects naive
software AES. The only remaining algorithmic-layer side-channel surface
is the GHASH/POLYVAL multiplier's 4-bit windowed table; that surface is
documented in the [CAUTION callout](#known-attacks) above and mitigated
by GCM-SIV's per-nonce key derivation.

A correct AES-256-GCM-SIV implementation through this library is
cryptographically secure for all foreseeable use cases under properly
generated keys.

---

## Cross-References

| Document | Description |
| -------- | ----------- |
| [index](./README.md) | Project Documentation index |
| [aes_audit](./aes_audit.md) | security audit results: algorithm correctness verification and side-channel analysis |
| [aes](./aes.md) | TypeScript API for AES (AES, AESCbc, AESCtr, AESGCM, AESGCMSIV, AESGenerator, Seal) |
| [asm_aes](./asm_aes.md) | WASM implementation: bitsliced 8-block kernel, tower-field S-box, GCM, GCM-SIV in AssemblyScript |


