//                  ▄▄▄▄▄▄▄▄▄▄
//           ▄████████████████████▄▄          ▒  ▄▀▀ ▒ ▒ █ ▄▀▄ ▀█▀ █ ▒ ▄▀▄ █▀▄
//        ▄██████████████████████ ▀████▄      ▓  ▓▀  ▓ ▓ ▓ ▓▄▓  ▓  ▓▀▓ ▓▄▓ ▓ ▓
//      ▄█████████▀▀▀     ▀███████▄▄███████▌  ▀▄ ▀▄▄ ▀▄▀ ▒ ▒ ▒  ▒  ▒ █ ▒ ▒ ▒ █
//     ▐████████▀   ▄▄▄▄     ▀████████▀██▀█▌
//     ████████      ███▀▀     ████▀  █▀ █▀       Leviathan Crypto Library
//     ███████▌    ▀██▀         ███
//      ███████   ▀███           ▀██ ▀█▄      Repository & Mirror:
//       ▀██████   ▄▄██            ▀▀  ██▄    github.com/xero/leviathan-crypto
//         ▀█████▄   ▄██▄             ▄▀▄▀    unpkg.com/leviathan-crypto
//            ▀████▄   ▄██▄
//              ▐████   ▐███                  Author: xero (https://x-e.ro)
//       ▄▄██████████    ▐███         ▄▄      License: MIT
//    ▄██▀▀▀▀▀▀▀▀▀▀     ▄████      ▄██▀
//  ▄▀  ▄▄█████████▄▄  ▀▀▀▀▀     ▄███         This file is provided completely
//   ▄██████▀▀▀▀▀▀██████▄ ▀▄▄▄▄████▀          free, "as is", and without
//  ████▀    ▄▄▄▄▄▄▄ ▀████▄ ▀█████▀  ▄▄▄▄     warranty of any kind. The author
//  █████▄▄█████▀▀▀▀▀▀▄ ▀███▄      ▄████      assumes absolutely no liability
//   ▀██████▀             ▀████▄▄▄████▀       for its {ab,mis,}use.
//                           ▀█████▀▀
//
// src/asm/sha2/sha512.ts
//
// SHA-512 and SHA-384 — AssemblyScript implementation
// Standard: FIPS 180-4, "Secure Hash Standard", August 2015
// URL: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
// Sections: §4.1.3 (functions), §4.2.3 (constants), §5.3.5/5.3.4 (IVs),
//           §6.4 (SHA-512 algorithm), §6.5 (SHA-384)
//
// SHA-384 shares all SHA-512 buffers and all round logic.
// The only differences are:
//   1. Initial hash values H0..H7 (§5.3.4 vs §5.3.5)
//   2. Output: SHA-512 returns 64 bytes; SHA-384 returns first 48 bytes
//
// Streaming API:
//   sha512Init()          — initialize SHA-512 IVs + clear partial/total state
//   sha384Init()          — initialize SHA-384 IVs + clear partial/total state
//   sha512Update(len)     — process len bytes from SHA512_INPUT_OFFSET (len ≤ 128)
//   sha512Final()         — pad, compress, write 64-byte digest to SHA512_OUT_OFFSET
//   sha384Final()         — pad, compress, write first 48 bytes to SHA512_OUT_OFFSET
//
// HMAC-SHA512/HMAC-SHA384 are in src/asm/sha2/hmac512.ts.

import {
	SHA512_H_OFFSET,
	SHA512_BLOCK_OFFSET,
	SHA512_W_OFFSET,
	SHA512_OUT_OFFSET,
	SHA512_INPUT_OFFSET,
	SHA512_PARTIAL_OFFSET,
	SHA512_TOTAL_OFFSET,
} from './buffers'

// ── FIPS 180-4 §4.2.3: SHA-512 round constants K[0..79] ─────────────────────
// K[t] = floor(cbrt(prime[t+1])) × 2^64  (first 80 primes starting from 2)

const K0:  i64 = 0x428a2f98d728ae22
const K1:  i64 = 0x7137449123ef65cd
const K2:  i64 = 0xb5c0fbcfec4d3b2f
const K3:  i64 = 0xe9b5dba58189dbbc
const K4:  i64 = 0x3956c25bf348b538
const K5:  i64 = 0x59f111f1b605d019
const K6:  i64 = 0x923f82a4af194f9b
const K7:  i64 = 0xab1c5ed5da6d8118
const K8:  i64 = 0xd807aa98a3030242
const K9:  i64 = 0x12835b0145706fbe
const K10: i64 = 0x243185be4ee4b28c
const K11: i64 = 0x550c7dc3d5ffb4e2
const K12: i64 = 0x72be5d74f27b896f
const K13: i64 = 0x80deb1fe3b1696b1
const K14: i64 = 0x9bdc06a725c71235
const K15: i64 = 0xc19bf174cf692694
const K16: i64 = 0xe49b69c19ef14ad2
const K17: i64 = 0xefbe4786384f25e3
const K18: i64 = 0x0fc19dc68b8cd5b5
const K19: i64 = 0x240ca1cc77ac9c65
const K20: i64 = 0x2de92c6f592b0275
const K21: i64 = 0x4a7484aa6ea6e483
const K22: i64 = 0x5cb0a9dcbd41fbd4
const K23: i64 = 0x76f988da831153b5
const K24: i64 = 0x983e5152ee66dfab
const K25: i64 = 0xa831c66d2db43210
const K26: i64 = 0xb00327c898fb213f
const K27: i64 = 0xbf597fc7beef0ee4
const K28: i64 = 0xc6e00bf33da88fc2
const K29: i64 = 0xd5a79147930aa725
const K30: i64 = 0x06ca6351e003826f
const K31: i64 = 0x142929670a0e6e70
const K32: i64 = 0x27b70a8546d22ffc
const K33: i64 = 0x2e1b21385c26c926
const K34: i64 = 0x4d2c6dfc5ac42aed
const K35: i64 = 0x53380d139d95b3df
const K36: i64 = 0x650a73548baf63de
const K37: i64 = 0x766a0abb3c77b2a8
const K38: i64 = 0x81c2c92e47edaee6
const K39: i64 = 0x92722c851482353b
const K40: i64 = 0xa2bfe8a14cf10364
const K41: i64 = 0xa81a664bbc423001
const K42: i64 = 0xc24b8b70d0f89791
const K43: i64 = 0xc76c51a30654be30
const K44: i64 = 0xd192e819d6ef5218
const K45: i64 = 0xd69906245565a910
const K46: i64 = 0xf40e35855771202a
const K47: i64 = 0x106aa07032bbd1b8
const K48: i64 = 0x19a4c116b8d2d0c8
const K49: i64 = 0x1e376c085141ab53
const K50: i64 = 0x2748774cdf8eeb99
const K51: i64 = 0x34b0bcb5e19b48a8
const K52: i64 = 0x391c0cb3c5c95a63
const K53: i64 = 0x4ed8aa4ae3418acb
const K54: i64 = 0x5b9cca4f7763e373
const K55: i64 = 0x682e6ff3d6b2b8a3
const K56: i64 = 0x748f82ee5defb2fc
const K57: i64 = 0x78a5636f43172f60
const K58: i64 = 0x84c87814a1f0ab72
const K59: i64 = 0x8cc702081a6439ec
const K60: i64 = 0x90befffa23631e28
const K61: i64 = 0xa4506cebde82bde9
const K62: i64 = 0xbef9a3f7b2c67915
const K63: i64 = 0xc67178f2e372532b
const K64: i64 = 0xca273eceea26619c
const K65: i64 = 0xd186b8c721c0c207
const K66: i64 = 0xeada7dd6cde0eb1e
const K67: i64 = 0xf57d4f7fee6ed178
const K68: i64 = 0x06f067aa72176fba
const K69: i64 = 0x0a637dc5a2c898a6
const K70: i64 = 0x113f9804bef90dae
const K71: i64 = 0x1b710b35131c471b
const K72: i64 = 0x28db77f523047d84
const K73: i64 = 0x32caab7b40c72493
const K74: i64 = 0x3c9ebe0a15c9bebc
const K75: i64 = 0x431d67c49c100d4c
const K76: i64 = 0x4cc5d4becb3e42b6
const K77: i64 = 0x597f299cfc657e2a
const K78: i64 = 0x5fcb6fab3ad6faec
const K79: i64 = 0x6c44198c4a475817

@inline
function kAt512(t: i32): i64 {
	switch (t) {
		case  0: return K0;  case  1: return K1;  case  2: return K2;  case  3: return K3
		case  4: return K4;  case  5: return K5;  case  6: return K6;  case  7: return K7
		case  8: return K8;  case  9: return K9;  case 10: return K10; case 11: return K11
		case 12: return K12; case 13: return K13; case 14: return K14; case 15: return K15
		case 16: return K16; case 17: return K17; case 18: return K18; case 19: return K19
		case 20: return K20; case 21: return K21; case 22: return K22; case 23: return K23
		case 24: return K24; case 25: return K25; case 26: return K26; case 27: return K27
		case 28: return K28; case 29: return K29; case 30: return K30; case 31: return K31
		case 32: return K32; case 33: return K33; case 34: return K34; case 35: return K35
		case 36: return K36; case 37: return K37; case 38: return K38; case 39: return K39
		case 40: return K40; case 41: return K41; case 42: return K42; case 43: return K43
		case 44: return K44; case 45: return K45; case 46: return K46; case 47: return K47
		case 48: return K48; case 49: return K49; case 50: return K50; case 51: return K51
		case 52: return K52; case 53: return K53; case 54: return K54; case 55: return K55
		case 56: return K56; case 57: return K57; case 58: return K58; case 59: return K59
		case 60: return K60; case 61: return K61; case 62: return K62; case 63: return K63
		case 64: return K64; case 65: return K65; case 66: return K66; case 67: return K67
		case 68: return K68; case 69: return K69; case 70: return K70; case 71: return K71
		case 72: return K72; case 73: return K73; case 74: return K74; case 75: return K75
		case 76: return K76; case 77: return K77; case 78: return K78; default: return K79
	}
}

// ── FIPS 180-4 §4.1.3: SHA-512 functions ────────────────────────────────────
//
// Rotation amounts (SHA-512 — DIFFERENT from SHA-256):
//   Σ0(28, 34, 39)   Σ1(14, 18, 41)
//   σ0( 1,  8, SHR7) σ1(19, 61, SHR6)
//
// DO NOT copy from SHA-256 — the rotation constants are different.

@inline function rotr64(x: i64, n: i64): i64 { return (x >>> n) | (x << (64 - n)) }

// Upper-case sigma (used in compression)
@inline function Sigma0_512(x: i64): i64 { return rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39) }
@inline function Sigma1_512(x: i64): i64 { return rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41) }

// Lower-case sigma (used in message schedule expansion)
@inline function sigma0_512(x: i64): i64 { return rotr64(x,  1) ^ rotr64(x,  8) ^ (x >>> 7) }
@inline function sigma1_512(x: i64): i64 { return rotr64(x, 19) ^ rotr64(x, 61) ^ (x >>> 6) }

// Choice and Majority (same structure as SHA-256, 64-bit operands)
@inline function Ch512 (e: i64, f: i64, g: i64): i64 { return (e & f) ^ (~e & g)           }
@inline function Maj512(a: i64, b: i64, c: i64): i64 { return (a & b) ^ (a & c) ^ (b & c)  }

// ── Big-endian 64-bit memory helpers ────────────────────────────────────────

@inline
function load64be(base: i32, byteOffset: i32): i64 {
	const off = base + byteOffset
	return ((load<u8>(off    ) as i64) << 56)
	     | ((load<u8>(off + 1) as i64) << 48)
	     | ((load<u8>(off + 2) as i64) << 40)
	     | ((load<u8>(off + 3) as i64) << 32)
	     | ((load<u8>(off + 4) as i64) << 24)
	     | ((load<u8>(off + 5) as i64) << 16)
	     | ((load<u8>(off + 6) as i64) <<  8)
	     |  (load<u8>(off + 7) as i64)
}

@inline
function store64be(base: i32, byteOffset: i32, v: i64): void {
	const off = base + byteOffset
	store<u8>(off,     (v >> 56) as u8)
	store<u8>(off + 1, (v >> 48) as u8)
	store<u8>(off + 2, (v >> 40) as u8)
	store<u8>(off + 3, (v >> 32) as u8)
	store<u8>(off + 4, (v >> 24) as u8)
	store<u8>(off + 5, (v >> 16) as u8)
	store<u8>(off + 6, (v >>  8) as u8)
	store<u8>(off + 7,  v        as u8)
}

// ── Compression function ─────────────────────────────────────────────────────
//
// Process one 1024-bit (128-byte) block at SHA512_BLOCK_OFFSET.
// Reads 16 big-endian u64 words, expands schedule W[0..79] into SHA512_W_OFFSET,
// runs 80 rounds, updates SHA512_H_OFFSET in place.

function sha512Compress(): void {
	// §6.4 step 1: prepare message schedule W[0..79]
	for (let t = 0; t < 16; t++) {
		store64be(SHA512_W_OFFSET, t * 8, load64be(SHA512_BLOCK_OFFSET, t * 8))
	}
	for (let t = 16; t < 80; t++) {
		const w = sigma1_512(load64be(SHA512_W_OFFSET, (t -  2) * 8))
		        +             load64be(SHA512_W_OFFSET, (t -  7) * 8)
		        + sigma0_512(load64be(SHA512_W_OFFSET, (t - 15) * 8))
		        +             load64be(SHA512_W_OFFSET, (t - 16) * 8)
		store64be(SHA512_W_OFFSET, t * 8, w)
	}

	// §6.4 step 2: initialize working variables from current hash state
	let a = load64be(SHA512_H_OFFSET,  0)
	let b = load64be(SHA512_H_OFFSET,  8)
	let c = load64be(SHA512_H_OFFSET, 16)
	let d = load64be(SHA512_H_OFFSET, 24)
	let e = load64be(SHA512_H_OFFSET, 32)
	let f = load64be(SHA512_H_OFFSET, 40)
	let g = load64be(SHA512_H_OFFSET, 48)
	let h = load64be(SHA512_H_OFFSET, 56)

	// §6.4 step 3: 80 rounds
	for (let t = 0; t < 80; t++) {
		const T1 = h + Sigma1_512(e) + Ch512(e, f, g) + kAt512(t) + load64be(SHA512_W_OFFSET, t * 8)
		const T2 = Sigma0_512(a) + Maj512(a, b, c)
		h = g; g = f; f = e; e = d + T1
		d = c; c = b; b = a; a = T1 + T2
	}

	// §6.4 step 4: add working variables to current hash value
	store64be(SHA512_H_OFFSET,  0, load64be(SHA512_H_OFFSET,  0) + a)
	store64be(SHA512_H_OFFSET,  8, load64be(SHA512_H_OFFSET,  8) + b)
	store64be(SHA512_H_OFFSET, 16, load64be(SHA512_H_OFFSET, 16) + c)
	store64be(SHA512_H_OFFSET, 24, load64be(SHA512_H_OFFSET, 24) + d)
	store64be(SHA512_H_OFFSET, 32, load64be(SHA512_H_OFFSET, 32) + e)
	store64be(SHA512_H_OFFSET, 40, load64be(SHA512_H_OFFSET, 40) + f)
	store64be(SHA512_H_OFFSET, 48, load64be(SHA512_H_OFFSET, 48) + g)
	store64be(SHA512_H_OFFSET, 56, load64be(SHA512_H_OFFSET, 56) + h)
}

// ── Initial hash values ──────────────────────────────────────────────────────

// SHA-512 (FIPS 180-4 §5.3.5)
const SHA512_H0: i64 = 0x6a09e667f3bcc908
const SHA512_H1: i64 = 0xbb67ae8584caa73b
const SHA512_H2: i64 = 0x3c6ef372fe94f82b
const SHA512_H3: i64 = 0xa54ff53a5f1d36f1
const SHA512_H4: i64 = 0x510e527fade682d1
const SHA512_H5: i64 = 0x9b05688c2b3e6c1f
const SHA512_H6: i64 = 0x1f83d9abfb41bd6b
const SHA512_H7: i64 = 0x5be0cd19137e2179

// SHA-384 (FIPS 180-4 §5.3.4)
const SHA384_H0: i64 = 0xcbbb9d5dc1059ed8
const SHA384_H1: i64 = 0x629a292a367cd507
const SHA384_H2: i64 = 0x9159015a3070dd17
const SHA384_H3: i64 = 0x152fecd8f70e5939
const SHA384_H4: i64 = 0x67332667ffc00b31
const SHA384_H5: i64 = 0x8eb44a8768581511
const SHA384_H6: i64 = 0xdb0c2e0d64f98fa7
const SHA384_H7: i64 = 0x47b5481dbefa4fa4

// ── Internal: load IVs and reset streaming state ─────────────────────────────

function loadIVs(
	h0: i64, h1: i64, h2: i64, h3: i64,
	h4: i64, h5: i64, h6: i64, h7: i64,
): void {
	store64be(SHA512_H_OFFSET,  0, h0)
	store64be(SHA512_H_OFFSET,  8, h1)
	store64be(SHA512_H_OFFSET, 16, h2)
	store64be(SHA512_H_OFFSET, 24, h3)
	store64be(SHA512_H_OFFSET, 32, h4)
	store64be(SHA512_H_OFFSET, 40, h5)
	store64be(SHA512_H_OFFSET, 48, h6)
	store64be(SHA512_H_OFFSET, 56, h7)
	store<i32>(SHA512_PARTIAL_OFFSET, 0)
	store<i64>(SHA512_TOTAL_OFFSET,   0)
}

// ── Public API ───────────────────────────────────────────────────────────────

// Initialize SHA-512 state. Must be called before sha512Update / sha512Final.
export function sha512Init(): void {
	loadIVs(SHA512_H0, SHA512_H1, SHA512_H2, SHA512_H3,
	        SHA512_H4, SHA512_H5, SHA512_H6, SHA512_H7)
}

// Initialize SHA-384 state. All SHA-512 buffers are shared; only IVs differ.
// Call sha384Final() (not sha512Final()) to get 48-byte output.
export function sha384Init(): void {
	loadIVs(SHA384_H0, SHA384_H1, SHA384_H2, SHA384_H3,
	        SHA384_H4, SHA384_H5, SHA384_H6, SHA384_H7)
}

// Hash len bytes from SHA512_INPUT_OFFSET into the running state.
// Contract: len ≤ 128 (size of SHA512_INPUT_OFFSET staging buffer).
// Caller must write input bytes to SHA512_INPUT_OFFSET before calling.
export function sha512Update(len: i32): void {
	store<i64>(SHA512_TOTAL_OFFSET, load<i64>(SHA512_TOTAL_OFFSET) + len)

	const partial = load<i32>(SHA512_PARTIAL_OFFSET)
	const space   = 128 - partial

	if (len <= space) {
		// All input fits in the current partial block
		if (len > 0) memory.copy(SHA512_BLOCK_OFFSET + partial, SHA512_INPUT_OFFSET, len)
		const newPartial = partial + len
		if (newPartial == 128) {
			sha512Compress()
			store<i32>(SHA512_PARTIAL_OFFSET, 0)
		} else {
			store<i32>(SHA512_PARTIAL_OFFSET, newPartial)
		}
	} else {
		// Input straddles a block boundary: fill rest of current block, compress,
		// then store remaining bytes (always < 128 since len ≤ 128).
		memory.copy(SHA512_BLOCK_OFFSET + partial, SHA512_INPUT_OFFSET, space)
		sha512Compress()
		const remaining = len - space
		memory.copy(SHA512_BLOCK_OFFSET, SHA512_INPUT_OFFSET + space, remaining)
		store<i32>(SHA512_PARTIAL_OFFSET, remaining)
	}
}

// Apply FIPS §5.1.2 padding, compress final block(s), write 64-byte digest
// to SHA512_OUT_OFFSET.
export function sha512Final(): void {
	const totalBytes = load<i64>(SHA512_TOTAL_OFFSET)
	let partial      = load<i32>(SHA512_PARTIAL_OFFSET)

	// §5.1.2: append 0x80 byte
	store<u8>(SHA512_BLOCK_OFFSET + partial, 0x80)
	partial++

	// If the 0x80 byte pushed us past byte 112 (no room for 16-byte length field),
	// zero the rest of this block and compress it.
	if (partial > 112) {
		memory.fill(SHA512_BLOCK_OFFSET + partial, 0, 128 - partial)
		sha512Compress()
		partial = 0
	}

	// Zero bytes [partial .. 111] to reach the 16-byte length field
	memory.fill(SHA512_BLOCK_OFFSET + partial, 0, 112 - partial)

	// §5.1.2: append 128-bit big-endian bit-length at bytes [112..127]
	// hi = totalBytes >> 61  (top 3 bits that overflow when multiplying by 8)
	// lo = totalBytes * 8    (= totalBytes << 3)
	const bitsHi: i64 = totalBytes >>> 61
	const bitsLo: i64 = totalBytes << 3
	store64be(SHA512_BLOCK_OFFSET, 112, bitsHi)
	store64be(SHA512_BLOCK_OFFSET, 120, bitsLo)

	sha512Compress()

	// Copy final hash state to SHA512_OUT_OFFSET (64 bytes)
	for (let i = 0; i < 8; i++) {
		store64be(SHA512_OUT_OFFSET, i * 8, load64be(SHA512_H_OFFSET, i * 8))
	}
}

// SHA-384 final: same padding as SHA-512, but output is first 48 bytes.
// sha384Init() must have been called at the start (SHA-384 IVs).
export function sha384Final(): void {
	sha512Final()
	// SHA512_OUT_OFFSET[0..47] is the SHA-384 digest (first 6 of 8 words).
	// SHA512_OUT_OFFSET[48..63] contains the remaining two words — callers
	// should read only [0..47]. No additional work needed here.
}
