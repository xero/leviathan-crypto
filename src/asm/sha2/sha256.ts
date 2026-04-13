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
// src/asm/sha2/sha256.ts
//
// SHA-256 — FIPS 180-4
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
//
// All state lives in fixed linear-memory buffers — no heap allocation.
// Buffer layout: see src/asm/sha2/buffers.ts
//
// Streaming API:
//   sha256Init()           — initialize H0..H7 + clear partial / total-bytes state
//   sha256Update(len: i32) — hash len bytes from SHA256_INPUT_OFFSET (len ≤ 64)
//   sha256Final()          — FIPS §5.1.1 padding + final compress → SHA256_OUT_OFFSET
//   sha256Hash(len: i32)   — sha256Init + sha256Update(len) + sha256Final (len ≤ 64)
//
// SHA256_INPUT_OFFSET is 64 bytes. For inputs longer than 64 bytes the caller
// must loop, writing ≤ 64 bytes per iteration and calling sha256Update() each time.
// sha256Final() handles the final partial block and all padding regardless of total length.

import {
	SHA256_H_OFFSET,
	SHA256_BLOCK_OFFSET,
	SHA256_W_OFFSET,
	SHA256_OUT_OFFSET,
	SHA256_INPUT_OFFSET,
	SHA256_PARTIAL_OFFSET,
	SHA256_TOTAL_OFFSET,
} from './buffers'

// ── FIPS 180-4 §4.2.2: SHA-256 round constants K[0..63] ─────────────────────
// K[t] = floor(cbrt(prime[t+1])) × 2^32  (first 64 primes starting from 2)
//
// K[54] = 0x5b9cca4f
// NOTE: dist/sha256.js in the leviathan source was observed to carry 0xe34d799b
// for K[54] — that value is WRONG. 0x5b9cca4f is correct per FIPS 180-4 §4.2.2.
// See sources/leviathan/docs/SHA256_AUDIT.md for the full forensic record.

const K0:  i32 = 0x428a2f98
const K1:  i32 = 0x71374491
const K2:  i32 = 0xb5c0fbcf
const K3:  i32 = 0xe9b5dba5
const K4:  i32 = 0x3956c25b
const K5:  i32 = 0x59f111f1
const K6:  i32 = 0x923f82a4
const K7:  i32 = 0xab1c5ed5
const K8:  i32 = 0xd807aa98
const K9:  i32 = 0x12835b01
const K10: i32 = 0x243185be
const K11: i32 = 0x550c7dc3
const K12: i32 = 0x72be5d74
const K13: i32 = 0x80deb1fe
const K14: i32 = 0x9bdc06a7
const K15: i32 = 0xc19bf174
const K16: i32 = 0xe49b69c1
const K17: i32 = 0xefbe4786
const K18: i32 = 0x0fc19dc6
const K19: i32 = 0x240ca1cc
const K20: i32 = 0x2de92c6f
const K21: i32 = 0x4a7484aa
const K22: i32 = 0x5cb0a9dc
const K23: i32 = 0x76f988da
const K24: i32 = 0x983e5152
const K25: i32 = 0xa831c66d
const K26: i32 = 0xb00327c8
const K27: i32 = 0xbf597fc7
const K28: i32 = 0xc6e00bf3
const K29: i32 = 0xd5a79147
const K30: i32 = 0x06ca6351
const K31: i32 = 0x14292967
const K32: i32 = 0x27b70a85
const K33: i32 = 0x2e1b2138
const K34: i32 = 0x4d2c6dfc
const K35: i32 = 0x53380d13
const K36: i32 = 0x650a7354
const K37: i32 = 0x766a0abb
const K38: i32 = 0x81c2c92e
const K39: i32 = 0x92722c85
const K40: i32 = 0xa2bfe8a1
const K41: i32 = 0xa81a664b
const K42: i32 = 0xc24b8b70
const K43: i32 = 0xc76c51a3
const K44: i32 = 0xd192e819
const K45: i32 = 0xd6990624
const K46: i32 = 0xf40e3585
const K47: i32 = 0x106aa070
const K48: i32 = 0x19a4c116
const K49: i32 = 0x1e376c08
const K50: i32 = 0x2748774c
const K51: i32 = 0x34b0bcb5
const K52: i32 = 0x391c0cb3
const K53: i32 = 0x4ed8aa4a
const K54: i32 = 0x5b9cca4f  // AUDIT: 0xe34d799b in dist/sha256.js is WRONG — SHA256_AUDIT.md
const K55: i32 = 0x682e6ff3
const K56: i32 = 0x748f82ee
const K57: i32 = 0x78a5636f
const K58: i32 = 0x84c87814
const K59: i32 = 0x8cc70208
const K60: i32 = 0x90befffa
const K61: i32 = 0xa4506ceb
const K62: i32 = 0xbef9a3f7
const K63: i32 = 0xc67178f2

@inline
function kAt(t: i32): i32 {
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
		case 60: return K60; case 61: return K61; case 62: return K62; default: return K63
	}
}

// ── FIPS 180-4 §4.1.2: SHA-256 functions ────────────────────────────────────

@inline function Ch (x: i32, y: i32, z: i32): i32 { return (x & y) ^ (~x & z)               }
@inline function Maj(x: i32, y: i32, z: i32): i32 { return (x & y) ^ (x & z) ^ (y & z)       }
@inline function bSig0(x: i32): i32 { return rotr<i32>(x,  2) ^ rotr<i32>(x, 13) ^ rotr<i32>(x, 22) }
@inline function bSig1(x: i32): i32 { return rotr<i32>(x,  6) ^ rotr<i32>(x, 11) ^ rotr<i32>(x, 25) }
@inline function sSig0(x: i32): i32 { return rotr<i32>(x,  7) ^ rotr<i32>(x, 18) ^ (x >>> 3)        }
@inline function sSig1(x: i32): i32 { return rotr<i32>(x, 17) ^ rotr<i32>(x, 19) ^ (x >>> 10)       }

// ── Big-endian memory helpers ───────────────────────────────────────────────

@inline
function load32be(base: i32, byteOffset: i32): i32 {
	const off = base + byteOffset
	return ((load<u8>(off)     as i32) << 24)
	     | ((load<u8>(off + 1) as i32) << 16)
	     | ((load<u8>(off + 2) as i32) <<  8)
	     |  (load<u8>(off + 3) as i32)
}

@inline
function store32be(base: i32, byteOffset: i32, v: i32): void {
	const off = base + byteOffset
	store<u8>(off,     (v >>> 24) & 0xff)
	store<u8>(off + 1, (v >>> 16) & 0xff)
	store<u8>(off + 2, (v >>>  8) & 0xff)
	store<u8>(off + 3,  v         & 0xff)
}

// ── Compression function ────────────────────────────────────────────────────
//
// Process one 512-bit block at blockOffset.
// Reads 16 big-endian u32 words, expands message schedule W[0..63] into
// SHA256_W_OFFSET, runs 64 rounds, updates SHA256_H_OFFSET in place.

function compress(blockOffset: i32): void {
	// §6.2.2 step 1: prepare message schedule W[0..63]
	for (let t = 0; t < 16; t++) {
		store32be(SHA256_W_OFFSET, t * 4, load32be(blockOffset, t * 4))
	}
	for (let t = 16; t < 64; t++) {
		const w = sSig1(load32be(SHA256_W_OFFSET, (t -  2) * 4))
		        +         load32be(SHA256_W_OFFSET, (t -  7) * 4)
		        + sSig0(load32be(SHA256_W_OFFSET, (t - 15) * 4))
		        +         load32be(SHA256_W_OFFSET, (t - 16) * 4)
		store32be(SHA256_W_OFFSET, t * 4, w)
	}

	// §6.2.2 step 2: initialize working variables from current hash state
	let a = load32be(SHA256_H_OFFSET,  0)
	let b = load32be(SHA256_H_OFFSET,  4)
	let c = load32be(SHA256_H_OFFSET,  8)
	let d = load32be(SHA256_H_OFFSET, 12)
	let e = load32be(SHA256_H_OFFSET, 16)
	let f = load32be(SHA256_H_OFFSET, 20)
	let g = load32be(SHA256_H_OFFSET, 24)
	let h = load32be(SHA256_H_OFFSET, 28)

	// §6.2.2 step 3: 64 rounds
	for (let t = 0; t < 64; t++) {
		const T1 = h + bSig1(e) + Ch(e, f, g) + kAt(t) + load32be(SHA256_W_OFFSET, t * 4)
		const T2 = bSig0(a) + Maj(a, b, c)
		h = g; g = f; f = e; e = d + T1
		d = c; c = b; b = a; a = T1 + T2
	}

	// §6.2.2 step 4: add working variables to current hash value
	store32be(SHA256_H_OFFSET,  0, load32be(SHA256_H_OFFSET,  0) + a)
	store32be(SHA256_H_OFFSET,  4, load32be(SHA256_H_OFFSET,  4) + b)
	store32be(SHA256_H_OFFSET,  8, load32be(SHA256_H_OFFSET,  8) + c)
	store32be(SHA256_H_OFFSET, 12, load32be(SHA256_H_OFFSET, 12) + d)
	store32be(SHA256_H_OFFSET, 16, load32be(SHA256_H_OFFSET, 16) + e)
	store32be(SHA256_H_OFFSET, 20, load32be(SHA256_H_OFFSET, 20) + f)
	store32be(SHA256_H_OFFSET, 24, load32be(SHA256_H_OFFSET, 24) + g)
	store32be(SHA256_H_OFFSET, 28, load32be(SHA256_H_OFFSET, 28) + h)
}

// ── FIPS 180-4 §5.3.3: Initial hash value H(0) ──────────────────────────────
// H[i] = floor(sqrt(prime[i+1])) × 2^32  (first 8 primes starting from 2)

const H0: i32 = 0x6a09e667
const H1: i32 = 0xbb67ae85
const H2: i32 = 0x3c6ef372
const H3: i32 = 0xa54ff53a
const H4: i32 = 0x510e527f
const H5: i32 = 0x9b05688c
const H6: i32 = 0x1f83d9ab
const H7: i32 = 0x5be0cd19

// ── Public API ──────────────────────────────────────────────────────────────

// Initialize SHA-256 state. Must be called before sha256Update / sha256Final.
export function sha256Init(): void {
	store32be(SHA256_H_OFFSET,  0, H0)
	store32be(SHA256_H_OFFSET,  4, H1)
	store32be(SHA256_H_OFFSET,  8, H2)
	store32be(SHA256_H_OFFSET, 12, H3)
	store32be(SHA256_H_OFFSET, 16, H4)
	store32be(SHA256_H_OFFSET, 20, H5)
	store32be(SHA256_H_OFFSET, 24, H6)
	store32be(SHA256_H_OFFSET, 28, H7)
	store<i32>(SHA256_PARTIAL_OFFSET, 0)
	store<i64>(SHA256_TOTAL_OFFSET, 0)
}

// Hash len bytes from SHA256_INPUT_OFFSET into the running state.
// Contract: len ≤ 64 (size of SHA256_INPUT_OFFSET staging buffer).
// Callers must write the input bytes to SHA256_INPUT_OFFSET before calling.
export function sha256Update(len: i32): void {
	store<i64>(SHA256_TOTAL_OFFSET, load<i64>(SHA256_TOTAL_OFFSET) + len)

	const partial = load<i32>(SHA256_PARTIAL_OFFSET)
	const space   = 64 - partial

	if (len <= space) {
		// All input fits in the current partial block
		if (len > 0) memory.copy(SHA256_BLOCK_OFFSET + partial, SHA256_INPUT_OFFSET, len)
		const newPartial = partial + len
		if (newPartial == 64) {
			compress(SHA256_BLOCK_OFFSET)
			store<i32>(SHA256_PARTIAL_OFFSET, 0)
		} else {
			store<i32>(SHA256_PARTIAL_OFFSET, newPartial)
		}
	} else {
		// Input straddles a block boundary: fill rest of current block, compress,
		// then store remaining bytes (always < 64 since len ≤ 64).
		memory.copy(SHA256_BLOCK_OFFSET + partial, SHA256_INPUT_OFFSET, space)
		compress(SHA256_BLOCK_OFFSET)
		const remaining = len - space
		memory.copy(SHA256_BLOCK_OFFSET, SHA256_INPUT_OFFSET + space, remaining)
		store<i32>(SHA256_PARTIAL_OFFSET, remaining)
	}
}

// Apply FIPS §5.1.1 padding, compress final block(s), write 32-byte digest
// to SHA256_OUT_OFFSET.
export function sha256Final(): void {
	const totalBytes = load<i64>(SHA256_TOTAL_OFFSET)
	let partial      = load<i32>(SHA256_PARTIAL_OFFSET)

	// §5.1.1: append 0x80 byte
	store<u8>(SHA256_BLOCK_OFFSET + partial, 0x80)
	partial++

	// If the 0x80 byte pushed us past byte 55 (no room for 8-byte length field),
	// zero the rest of this block and compress it.
	if (partial > 56) {
		memory.fill(SHA256_BLOCK_OFFSET + partial, 0, 64 - partial)
		compress(SHA256_BLOCK_OFFSET)
		partial = 0
	}

	// Zero bytes [partial .. 55] to reach the 8-byte length field
	memory.fill(SHA256_BLOCK_OFFSET + partial, 0, 56 - partial)

	// §5.1.1: append 64-bit big-endian bit-length at bytes [56..63]
	// bitLen = totalBytes × 8 (i64, split into high/low 32-bit words)
	const bitLen = totalBytes << 3
	store32be(SHA256_BLOCK_OFFSET, 56, i32(bitLen >>> 32))
	store32be(SHA256_BLOCK_OFFSET, 60, i32(bitLen))

	compress(SHA256_BLOCK_OFFSET)

	// Copy final hash state to SHA256_OUT_OFFSET
	for (let i = 0; i < 8; i++) {
		store32be(SHA256_OUT_OFFSET, i * 4, load32be(SHA256_H_OFFSET, i * 4))
	}
}

// Convenience: sha256Init + sha256Update(len) + sha256Final for inputs that fit in
// SHA256_INPUT_OFFSET in a single call (len ≤ 64).
// Caller writes input to SHA256_INPUT_OFFSET, calls sha256Hash(len), reads SHA256_OUT_OFFSET.
export function sha256Hash(len: i32): void {
	sha256Init()
	sha256Update(len)
	sha256Final()
}
