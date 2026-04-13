# XChaCha20-Poly1305 Algorithm Reference

> [!NOTE]
> Algorithm specification and known-attack survey for XChaCha20-Poly1305 AEAD, covering the ChaCha20 block function, Poly1305 MAC, HChaCha20 subkey derivation, ARX design properties, and cryptanalytic results. Sources: RFC 8439 (Nir & Langley, 2018), draft-irtf-cfrg-xchacha-03 (Arciszewski, 2020), Bernstein's original ChaCha and Poly1305 papers (2005, 2008).

> ### Table of Contents
> - [1. Algorithm Overview](#1-algorithm-overview)
> - [2. Algorithm Specification](#2-algorithm-specification)
> - [3. XChaCha20-Poly1305](#3-xchacha20-poly1305)
> - [4. ARX Design and Implementation Properties](#4-arx-design-and-implementation-properties)
> - [5. Known Attacks](#5-known-attacks)

---

## 1. Algorithm Overview

### Origins and Design Goals

ChaCha20 is a stream cipher designed by Daniel J. Bernstein (University of Illinois at Chicago) in 2008, derived from his earlier Salsa20 cipher (2005, eSTREAM finalist). Poly1305 is a one-time message authentication code also designed by Bernstein, introduced in his 2005 paper "The Poly1305-AES message-authentication code." The two were combined into the AEAD construction ChaCha20-Poly1305 by Adam Langley (Google) around 2013 and subsequently standardized as RFC 8439 (June 2018), obsoleting RFC 7539.

Bernstein's stated design priorities for ChaCha20:

**Software speed on constrained hardware.** AES requires either dedicated hardware (AES-NI) for competitive performance, or is slow and vulnerable on platforms without it. ChaCha20 uses only 32-bit addition, XOR, and rotation — operations that are uniformly fast across ARM, MIPS, embedded, and general-purpose CPUs.

**Timing side-channel resistance by construction.** The ARX (Add-Rotate-XOR) design contains no data-dependent memory accesses, no table lookups indexed by secret data, and no data-dependent branches. This is a structural property of the algorithm, not an implementation technique.

**Simplicity and auditability.** The full cipher fits in a handful of lines of readable code.

The `X` prefix in XChaCha20 denotes the extended nonce variant: nonce extended from 96 bits to 192 bits via the HChaCha20 subkey derivation function. This is the variant leviathan uses, as it enables safe random nonce generation per message.

### Historical Context: The Standby Cipher Problem

RFC 8439's introduction documents the motivation explicitly. AES became the near-universal encryption standard, with no widely-deployed alternative. If future cryptanalysis weakens AES, or if implementation flaws are discovered in AES-NI paths, there is no practical fallback. ChaCha20-Poly1305 was adopted by major TLS stacks (OpenSSL, BoringSSL), operating systems, and protocols (TLS 1.3, WireGuard, SSH) specifically to address this single-point-of-failure concern.

### Design Lineage: Salsa20 → ChaCha20

ChaCha20 is a variant of Salsa20 with improved diffusion per round. The key structural change is the quarter round: ChaCha's mixing differs from Salsa20's, achieving better avalanche in fewer operations. Both ciphers share the same ARX core, 20-round structure, and 512-bit block size. The ChaCha family is sometimes described as "Salsa20 with better mixing."

### ChaCha20-Poly1305 vs AES-GCM

| Property | XChaCha20-Poly1305 | AES-256-GCM |
|----------|-------------------|-------------|
| Key size | 256 bits | 128 or 256 bits |
| Nonce size | 192 bits (XChaCha) | 96 bits |
| Tag size | 128 bits | 128 bits |
| Nonce collision risk (random) | ~2⁹⁶ msgs before 50% collision | ~2⁴⁸ msgs before 50% collision (birthday) |
| Hardware acceleration required for safety | No | Yes (timing side-channels without AES-NI) |
| Software performance (no HW accel) | Fast (ARX) | Slow |
| Software performance (with HW accel) | Fast | Faster |
| Nonce misuse consequence | Keystream reuse (plaintext recovery) | Keystream reuse + auth key leak |

The critical asymmetry is in the nonce misuse row. GCM's polynomial authenticator uses the nonce to derive the authentication key (H). Nonce reuse under GCM exposes H, allowing tag forgery for all past and future messages under that key — a catastrophic failure mode beyond mere confidentiality loss. ChaCha20-Poly1305 generates a fresh one-time Poly1305 key per message using the cipher itself; nonce reuse still recovers plaintexts (bad), but does not break authentication globally.

---

## 2. Algorithm Specification

### 2.1 Parameters

| Parameter | Value |
|-----------|-------|
| Key | 256 bits |
| Nonce (ChaCha20-Poly1305) | 96 bits |
| Nonce (XChaCha20-Poly1305) | 192 bits |
| Block size | 512 bits (64 bytes) |
| Counter | 32 bits, starts at 1 for AEAD (0 reserved for Poly1305 key gen) |
| Tag | 128 bits |
| Max plaintext | (2³² − 1) × 64 bytes ≈ 256 GiB |

### 2.2 ChaCha State

The ChaCha20 state is a 4×4 matrix of 32-bit little-endian words, laid out as:

```
 0  1  2  3     "expa"  "nd 3"  "2-by"  "te k"      ← constants (row 0)
 4  5  6  7     key[0]  key[1]  key[2]  key[3]       ← key words 0–3 (row 1)
 8  9 10 11     key[4]  key[5]  key[6]  key[7]       ← key words 4–7 (row 2)
12 13 14 15     counter nonce0  nonce1  nonce2        ← counter + nonce (row 3)
```

The four constants are ASCII bytes of `"expand 32-byte k"` — the "nothing up my sleeve" string from Bernstein's original spec. As 32-bit little-endian words:

```
0x61707865  0x3320646e  0x79622d32  0x6b206574
```

The 256-bit key fills words 4–11 as eight 32-bit little-endian words. The 32-bit counter fills word 12 (initialized to 1 in AEAD mode). The 96-bit nonce fills words 13–15 as three 32-bit little-endian words.

### 2.3 Quarter Round

The quarter round (QR) is the atomic operation of ChaCha20. It takes four 32-bit words (a, b, c, d) and produces four new words using only addition mod 2³², XOR, and left rotation:

```
a += b;  d ^= a;  d <<<= 16;
c += d;  b ^= c;  b <<<= 12;
a += b;  d ^= a;  d <<<= 8;
c += d;  b ^= c;  b <<<= 7;
```

Where `+` is addition mod 2³², `^` is XOR, and `<<<` is 32-bit left rotation.

All four rotation constants (16, 12, 8, 7) were chosen by Bernstein to maximize diffusion: each output bit depends on every input bit as quickly as possible. The 16 and 8 rotations are particularly efficient on architectures with `BSWAP`/`REV` instructions since they reduce to byte swaps.

### 2.4 Block Function

The ChaCha20 block function applies 20 rounds to the 4×4 state, alternating between column rounds and diagonal rounds. Each round consists of four quarter rounds applied in parallel to four (a,b,c,d) groups.

**Column round** — four vertical columns:

```
QR(0, 4,  8, 12)
QR(1, 5,  9, 13)
QR(2, 6, 10, 14)
QR(3, 7, 11, 15)
```

**Diagonal round** — four diagonals (wrapping):

```
QR(0, 5, 10, 15)
QR(1, 6, 11, 12)
QR(2, 7,  8, 13)
QR(3, 4,  9, 14)
```

20 rounds = 10 column rounds interleaved with 10 diagonal rounds. After 20 rounds, the output state is added word-by-word (mod 2³²) to the initial state, producing the 64-byte keystream block:

```
output[i] = working_state[i] + initial_state[i]   for i = 0..15
```

The final addition is critical: it prevents the function from being invertible (running the rounds backwards with only the output would recover the input without it), and it provides the "add" in the ARX chain that links the permutation output back to the key material.

### 2.5 Stream Encryption

ChaCha20 encryption is straightforward counter-mode stream cipher operation:

```
for each 64-byte block i (starting at counter = 1 in AEAD mode):
    keystream_block = chacha20_block(key, counter + i, nonce)
    ciphertext[i*64 : (i+1)*64] = plaintext[i*64 : (i+1)*64] ^ keystream_block
```

For a final partial block, only the needed bytes of the keystream block are used; the remainder is discarded.

Decryption is identical — XOR with the same keystream regenerated from the same (key, nonce, counter).

### 2.6 Poly1305

Poly1305 is a one-time MAC operating over GF(2¹³⁰ − 5). It takes a 32-byte one-time key and a message of arbitrary length, and produces a 16-byte tag.

#### Key Structure

The 32-byte one-time key is split into two 128-bit halves:

- **r** (bytes 0–15): the polynomial key, clamped before use
- **s** (bytes 16–31): the final addition constant

**Clamping r:** certain bits of r are forced to zero before use, ensuring the key lies in a subgroup that prevents certain algebraic attacks. The clamping rule clears bits at specific positions via byte-level masks:

```
r[3]  &= 0x0f
r[4]  &= 0xfc
r[7]  &= 0x0f
r[8]  &= 0xfc
r[11] &= 0x0f
r[12] &= 0xfc
r[15] &= 0x0f
```

All remaining bytes are unmasked (effectively `& 0xff`), which is correct per RFC 8439 §2.5.

#### MAC Algorithm

The message is processed in 16-byte chunks. Each chunk is treated as a little-endian integer with a high bit appended beyond the top byte (making the value at most 17 bytes / 136 bits). The accumulator `h` is maintained over GF(2¹³⁰ − 5):

```
h = 0
for each 16-byte block m_i:
    n = little_endian_to_int(m_i) | (1 << (8 * len(m_i)))
    h = (h + n) * r  mod (2¹³⁰ − 5)
tag = (h + s) mod 2¹²⁸
```

The final partial block (if the message length is not a multiple of 16) is padded on the right with zeros, and the `1` bit is set at position `8 * actual_len` rather than `8 * 16`. The `h + s` final step serializes `h` back to 128 bits by discarding the upper 2 bits.

The prime 2¹³⁰ − 5 was chosen because it allows efficient arithmetic: modular reduction can be done using the identity `2¹³⁰ ≡ 5 (mod 2¹³⁰ − 5)`, so carrying out of the 130-bit accumulator multiplies the overflow by 5 and adds back into the lower 130 bits — a cheap operation.

### 2.7 Poly1305 Key Generation

In the AEAD construction, the one-time Poly1305 key is derived from the encryption key and nonce using ChaCha20 itself, rather than being provided externally. This ensures a unique MAC key per (key, nonce) pair without requiring a separate key distribution mechanism.

The derivation uses the ChaCha20 block function with counter = 0:

```
poly1305_key_block = chacha20_block(key, counter=0, nonce)
r = poly1305_key_block[0:16]   (first 128 bits, clamped)
s = poly1305_key_block[16:32]  (next 128 bits)
```

The remaining 32 bytes of the 64-byte block output are discarded. Counter 0 is consumed by key generation; encryption begins at counter 1.

### 2.8 AEAD Construction (ChaCha20-Poly1305)

The full AEAD construction authenticates additional data (AAD) alongside the ciphertext, producing a ciphertext + tag that is unforgeable without the key.

**Encryption:**

```
Input:  key (32B), nonce (12B), plaintext, aad
Output: ciphertext, tag

1. poly1305_key = chacha20_block(key, counter=0, nonce)[0:32]
2. ciphertext = chacha20_encrypt(key, counter=1, nonce, plaintext)
3. mac_data = pad16(aad)
             ‖ pad16(ciphertext)
             ‖ le64(len(aad))
             ‖ le64(len(ciphertext))
4. tag = poly1305(poly1305_key, mac_data)
```

Where `pad16(x)` pads `x` with zero bytes to the next 16-byte boundary (no-op if already aligned), and `le64(n)` is the 8-byte little-endian encoding of integer n.

**Decryption:**

```
Input:  key (32B), nonce (12B), ciphertext, tag, aad
Output: plaintext, or authentication failure

1. poly1305_key = chacha20_block(key, counter=0, nonce)[0:32]
2. Reconstruct mac_data from aad and ciphertext (same as encryption step 3)
3. expected_tag = poly1305(poly1305_key, mac_data)
4. if constant_time_compare(tag, expected_tag) fails: return FAIL
5. plaintext = chacha20_encrypt(key, counter=1, nonce, ciphertext)
```

Tag verification **must** be performed before decryption begins in implementations that allow partial output. The tag is checked before plaintext is returned to the caller in any case.

> [!IMPORTANT]
> The MAC data layout (`pad16(aad) ‖ pad16(ciphertext) ‖ le64(len(aad)) ‖ le64(len(ciphertext))`) is a specific wire format. The length fields are necessary to prevent ambiguity: without them, `aad="AA", ct="BBBB"` and `aad="AABB", ct="BB"` would produce identical mac_data.

---

## 3. XChaCha20-Poly1305

### 3.1 The Nonce Problem

Standard ChaCha20-Poly1305 uses a 96-bit nonce. With random nonce generation and the birthday bound, a (key, nonce) collision becomes probable after approximately 2⁴⁸ messages — a real concern for high-volume or long-lived session keys. The typical mitigation is a monotonic counter nonce, but this requires stateful nonce management, which complicates distributed or stateless systems.

XChaCha20 solves this by extending the nonce to 192 bits. With a 192-bit random nonce, the birthday collision threshold rises to 2⁹⁶ messages (roughly 7.3 × 10²⁸) — effectively infinite for any practical purpose. Applications can generate nonces at random per message and discard all nonce state.

### 3.2 HChaCha20

HChaCha20 is the subkey derivation function at the heart of XChaCha20. It is derived from HSalsa20 (Bernstein, 2011), adapted for the ChaCha state layout.

HChaCha20 initializes a ChaCha state identically to ChaCha20 but with the 32-bit counter position replaced by the first 32 bits of the 128-bit input nonce (the block counter slot is consumed by nonce material, and there is no counter):

```
ChaCha20 state layout:
  [constants | key (8 words) | counter | nonce (3 words)]

HChaCha20 state layout:
  [constants | key (8 words) | nonce[0..3] (4 words)]
```

The full 20-round ChaCha permutation is then applied. Rather than adding back the initial state at the end (as ChaCha20's block function does), HChaCha20 extracts only the **first and last rows** of the post-round state as the output subkey:

```
output = state[0..3] ‖ state[12..15]   (8 × 32-bit words = 256 bits)
```

The selection of these specific indices (0–3 and 12–15) is not arbitrary — it mirrors the approach from HSalsa20, where the corresponding indices were chosen to make a security proof work. The proof (from the XSalsa20 paper, Bernstein 2011) shows that extracting output from a public computation at positions corresponding to the constants and nonce slots produces a PRF-secure subkey, given that the underlying permutation is secure. The same argument carries over directly to HChaCha20:

```
HSalsa20 output indices: 0, 5, 10, 15, 6, 7, 8, 9
HChaCha20 output indices: 0, 1, 2, 3, 12, 13, 14, 15
```

The middle rows (state[4..11], the key material) are deliberately discarded from the output, ensuring that even with knowledge of the subkey, the original key cannot be recovered.

**HChaCha20 state initialization:**

```
[0..3]   "expand 32-byte k" constants
[4..11]  256-bit key (8 little-endian u32 words)
[12..15] first 128 bits (16 bytes) of the 192-bit XChaCha nonce
```

No counter. The remaining 64 bits of the 192-bit nonce are not used here — they are passed directly to ChaCha20 as described in §3.3.

### 3.3 XChaCha20 Nonce Split

The 192-bit XChaCha nonce is split:

- **bytes 0–15** (128 bits) → HChaCha20 input nonce, used to derive the subkey
- **bytes 16–23** (64 bits) → ChaCha20 nonce suffix, placed at bytes 4–11 of a zeroed 12-byte nonce:

```
chacha20_nonce = 0x00000000 ‖ xchacha_nonce[16:24]
```

The four zero bytes in the nonce prefix ensure the counter and nonce fields don't alias; the actual counter starts at 1 for AEAD encryption.

### 3.4 AEAD_XChaCha20_Poly1305

The full XChaCha20-Poly1305 AEAD construction:

```
Input:  key (32B), nonce (24B), plaintext, aad
Output: ciphertext, tag

1. subkey = HChaCha20(key, nonce[0:16])
2. chacha_nonce = 0x00000000 ‖ nonce[16:24]   (12 bytes)
3. (ciphertext, tag) = AEAD_ChaCha20_Poly1305(subkey, chacha_nonce, plaintext, aad)
```

Decryption mirrors this exactly, substituting the AEAD decrypt in step 3.

The construction is composable: once the subkey is derived, the remainder is a standard ChaCha20-Poly1305 AEAD call. Implementations that already have ChaCha20-Poly1305 need only add HChaCha20 to gain the extended nonce variant.

---

## 4. ARX Design and Implementation Properties

### 4.1 The ARX Primitive

ChaCha20 uses exclusively three 32-bit operations:

- **A**: addition mod 2³²
- **R**: left rotation by a fixed constant
- **X**: XOR

There are no S-boxes, no lookup tables, no data-dependent memory accesses, and no branches. Every operation executes unconditionally on register operands. The cipher has no notion of "lookup" at any level.

This is a structural difference from block ciphers like AES or Serpent. AES's SubBytes step — even with AES-NI — requires a table operation in software fallback paths. Serpent's bitslice S-boxes eliminate this via boolean circuits, but at the cost of significant code complexity. ChaCha20 achieves timing-channel safety through the simplicity of the operations themselves.

### 4.2 Side-Channel Properties

**Cache-timing:** None possible by construction. There are no memory accesses indexed by secret data. The state lives entirely in registers.

**Branch-timing:** None possible by construction. There are no data-dependent branches.

**Power analysis (DPA):** The ARX structure mixes key material into every word in every round, providing natural avalanche that complicates DPA correlation. However, dedicated DPA mitigation (masking, blinding) is outside the algorithm's scope and depends on the deployment platform.

**Timing of Poly1305 verification:** The constant-time comparison of the authentication tag is an **implementation** requirement, not an algorithm property. A naive `memcmp` on the tag allows timing oracle attacks against the MAC. Implementations must use a constant-time comparison (e.g. XOR-accumulate over all bytes with no early return).

### 4.3 Performance

ChaCha20's 512-bit block size processes 64 bytes per block function call, versus AES's 128-bit (16-byte) block size. For equivalent plaintext volume, ChaCha20 makes fewer block function calls.

The quarter round's four operations are highly parallelizable: on modern superscalar CPUs, multiple QRs can execute in parallel since the four column-round QRs operate on independent word groups. SIMD implementations (leviathan's 4-wide inter-block parallelism using `v128`) vectorize across multiple blocks simultaneously, processing four blocks in parallel.

Without hardware acceleration, ChaCha20 typically outperforms AES. With AES-NI, AES-GCM is faster on hardware that has it. On ARM (common in mobile and embedded), ChaCha20 is frequently faster even against hardware AES, due to ARM's AES instructions having higher latency than the NEON-vectorized ChaCha20 path.

---

## 5. Known Attacks

### 5.1 Differential Cryptanalysis

**Applicability:** Reduced-round only.

Standard differential cryptanalysis does not extend to 20-round ChaCha20. The best differential distinguishers in the literature reach at most 7 rounds with impractical data and time requirements. The 13-round margin beyond the best distinguisher provides substantial security.

### 5.2 Linear Cryptanalysis

**Applicability:** Not directly applicable.

Stream ciphers do not have the block cipher structure that classical linear cryptanalysis targets. Correlation attacks on the keystream (the analogue for stream ciphers) have not produced results beyond heavily reduced-round variants.

### 5.3 Differential-Linear Attacks (Best Known)

**Best published result:** Shi et al. (2012) — 7-round distinguisher requiring 2²³ chosen plaintexts. Choudhuri and Maitra (2016) achieved marginal improvements on 7-round differential-linear attacks.

No distinguisher beyond 7 rounds of ChaCha20 is published as of this writing. Full 20-round ChaCha20 has a **13-round security margin** against the best known attack.

| Attack | Rounds | Data | Practical? |
|--------|--------|------|------------|
| Differential-linear distinguisher (Shi 2012) | 7 | 2²³ CP | No |
| Differential-linear key recovery (Choudhuri & Maitra 2016) | 7 | — | No |

All results remain far from the full 20 rounds.

### 5.4 Rotational Cryptanalysis

**Applicability:** Theoretical, reduced rounds only.

Rotational cryptanalysis (Khovratovich & Nikolić, 2010) attempts to exploit the rotation constants in ARX ciphers. Applied to ChaCha20, no results beyond heavily reduced rounds have been published.

### 5.5 Polynomial Attacks on Poly1305

**Applicability:** Implementation-specific; requires nonce reuse.

The one-time nature of the Poly1305 key (fresh derivation per message) is the primary security assumption. If the Poly1305 key is ever reused — due to nonce reuse in the ChaCha20 key derivation step — two messages share the same (r, s), allowing an algebraic attack to recover r from the two tag/ciphertext pairs and then forge tags.

The attack: given `tag₁ = h(m₁) * r + s` and `tag₂ = h(m₂) * r + s`, compute `tag₁ − tag₂ = (h(m₁) − h(m₂)) * r`, and solve for r. This directly recovers the polynomial key and enables universal forgery.

**Mitigation:** XChaCha20's 192-bit random nonce makes nonce reuse negligible in probability. The attack is only relevant if nonce generation is broken or deterministic nonce management fails.

### 5.6 Nonce Misuse

**Consequence:** Keystream reuse + Poly1305 key exposure.

Nonce reuse (encrypting two messages with the same key and nonce) under ChaCha20-Poly1305 produces two ciphertexts XOR'd with identical keystreams. Crib-dragging (known-plaintext XOR) recovers both plaintexts. Additionally, as described in §5.5, the shared Poly1305 key is recoverable, enabling authentication bypass.

This is a misuse attack, not a cryptanalytic one; the algorithm provides no nonce-misuse resistance by design. XChaCha20's extended nonce is the correct mitigation.

Birthday-bound analysis for nonce collision under XChaCha20:

| Nonce size | 50% collision after | At 10⁹ msgs/sec, time to 50% |
|---|---|---|
| 96-bit (ChaCha20) | ~2⁴⁸ msgs | ~9 days |
| 192-bit (XChaCha20) | ~2⁹⁶ msgs | ~2.5 × 10¹⁸ years |

### 5.7 Forgery Bound

The forgery probability for Poly1305 is bounded by:

```
P_forgery ≤ ⌈l/16⌉ / 2¹⁰⁶
```

where l is the message length in bytes.

| Message size | Blocks | Forgery probability |
|---|---|---|
| 64 bytes | 4 | 4 / 2¹⁰⁶ ≈ 2⁻¹⁰⁴ |
| 1 KB | 64 | 2⁶ / 2¹⁰⁶ = 2⁻¹⁰⁰ |
| 64 KB | 4,096 | 2¹² / 2¹⁰⁶ = 2⁻⁹⁴ |
| 1 MB | 65,536 | 2¹⁶ / 2¹⁰⁶ = 2⁻⁹⁰ |

### 5.8 Overall Security Assessment

XChaCha20-Poly1305 security posture as of 2026:

| Attack class | Best result | Threat level |
|---|---|---|
| Differential cryptanalysis | 7 rounds (infeasible data) | None |
| Linear / correlation | No meaningful results | None |
| Differential-linear (best) | 7 rounds, 13-round margin | None |
| Rotational | Reduced rounds only | None |
| Poly1305 algebraic | Requires nonce reuse | None (with XChaCha nonce) |
| Nonce misuse | Keystream reuse + MAC break | Mitigated by 192-bit nonce |
| Side-channel (cache/branch) | None by construction | None at algorithm level |

**Security margin:** The best published attacks reach 7 of 20 rounds — a 13-round margin. ChaCha20 has been deployed at enormous scale (TLS 1.3, WireGuard, Signal, Android full-disk encryption) with no known practical weaknesses in the full-round construction.

---


## Cross-References

| Document | Description |
| -------- | ----------- |
| [index](./README.md) | Project Documentation index |
| [chacha_audit](./chacha_audit.md) | security audit results: algorithm correctness verification and side-channel analysis |
| [chacha20](./chacha20.md) | TypeScript API for XChaCha20-Poly1305 (ChaCha, Seal, raw modes) |
| [asm_chacha](./asm_chacha.md) | WASM implementation: quarter round, block function, Poly1305, AEAD in AssemblyScript |

