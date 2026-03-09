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
// src/asm/chacha/chacha20.ts
//
// ChaCha20 stream cipher — AssemblyScript implementation
// Standard: RFC 8439, May 2018
// URL: https://www.rfc-editor.org/rfc/rfc8439
//
// State layout (RFC 8439 §2.2):
//   words  0– 3: constants "expa" "nd 3" "2-by" "te k"  (0x61707865 etc.)
//   words  4–11: key (256 bits = 8 words, little-endian)
//   word  12:    counter (u32, starts at 1 for encryption per RFC §2.3)
//   words 13–15: nonce (96 bits = 3 words, little-endian)
//
// Endianness: ChaCha20 uses little-endian throughout. load<u32> / store<u32>
// in WASM are native little-endian — no byte-swapping needed.
// Rotation: ChaCha20 uses LEFT rotation (rotl).

import {
	KEY_OFFSET,
	CHUNK_PT_OFFSET, CHUNK_CT_OFFSET, CHUNK_SIZE,
	CHACHA_NONCE_OFFSET, CHACHA_CTR_OFFSET,
	CHACHA_BLOCK_OFFSET, CHACHA_STATE_OFFSET,
	POLY_KEY_OFFSET,
	XCHACHA_NONCE_OFFSET, XCHACHA_SUBKEY_OFFSET,
} from './buffers'

// ── Constants ─────────────────────────────────────────────────────────────────
// "expand 32-byte k" in ASCII, split into four LE 32-bit words (RFC §2.2)
const C0: u32 = 0x61707865  // "expa"
const C1: u32 = 0x3320646e  // "nd 3"
const C2: u32 = 0x79622d32  // "2-by"
const C3: u32 = 0x6b206574  // "te k"

// ── Helpers ───────────────────────────────────────────────────────────────────

@inline
function rotl32(x: u32, n: u32): u32 {
	return (x << n) | (x >>> (32 - n))
}

// ── Quarter round ─────────────────────────────────────────────────────────────
// RFC 8439 §2.1
@inline
function qr(base: i32, a: i32, b: i32, c: i32, d: i32): void {
	let av = load<u32>(base + a * 4)
	let bv = load<u32>(base + b * 4)
	let cv = load<u32>(base + c * 4)
	let dv = load<u32>(base + d * 4)

	av += bv; dv ^= av; dv = rotl32(dv, 16)
	cv += dv; bv ^= cv; bv = rotl32(bv, 12)
	av += bv; dv ^= av; dv = rotl32(dv,  8)
	cv += dv; bv ^= cv; bv = rotl32(bv,  7)

	store<u32>(base + a * 4, av)
	store<u32>(base + b * 4, bv)
	store<u32>(base + c * 4, cv)
	store<u32>(base + d * 4, dv)
}

// ── Double round ──────────────────────────────────────────────────────────────
// One double round = column round + diagonal round (RFC §2.1)
// 20 rounds total = 10 double rounds
@inline
function doubleRound(base: i32): void {
	// Column rounds
	qr(base, 0, 4,  8, 12)
	qr(base, 1, 5,  9, 13)
	qr(base, 2, 6, 10, 14)
	qr(base, 3, 7, 11, 15)
	// Diagonal rounds
	qr(base, 0, 5, 10, 15)
	qr(base, 1, 6, 11, 12)
	qr(base, 2, 7,  8, 13)
	qr(base, 3, 4,  9, 14)
}

// ── Block function ────────────────────────────────────────────────────────────
// Produce one 64-byte keystream block from the current state.
// RFC §2.2: copy → 10 double rounds → add initial state
function block(): void {
	memory.copy(CHACHA_BLOCK_OFFSET, CHACHA_STATE_OFFSET, 64)

	for (let i = 0; i < 10; i++) {
		doubleRound(CHACHA_BLOCK_OFFSET)
	}

	for (let i = 0; i < 16; i++) {
		store<u32>(CHACHA_BLOCK_OFFSET + i * 4,
			load<u32>(CHACHA_BLOCK_OFFSET + i * 4) +
			load<u32>(CHACHA_STATE_OFFSET + i * 4))
	}
}

// ── Key and nonce setup ───────────────────────────────────────────────────────

export function chachaLoadKey(): void {
	const s = CHACHA_STATE_OFFSET

	// words 0–3: constants (RFC §2.2)
	store<u32>(s +  0, C0)
	store<u32>(s +  4, C1)
	store<u32>(s +  8, C2)
	store<u32>(s + 12, C3)

	// words 4–11: key (8 × u32, loaded LE from KEY_OFFSET)
	for (let i = 0; i < 8; i++) {
		store<u32>(s + 16 + i * 4, load<u32>(KEY_OFFSET + i * 4))
	}

	// word 12: counter
	store<u32>(s + 48, load<u32>(CHACHA_CTR_OFFSET))

	// words 13–15: nonce (3 × u32, loaded LE from CHACHA_NONCE_OFFSET)
	for (let i = 0; i < 3; i++) {
		store<u32>(s + 52 + i * 4, load<u32>(CHACHA_NONCE_OFFSET + i * 4))
	}
}

export function chachaSetCounter(ctr: u32): void {
	store<u32>(CHACHA_CTR_OFFSET, ctr)
	store<u32>(CHACHA_STATE_OFFSET + 48, ctr)
}

export function chachaResetCounter(): void {
	chachaSetCounter(1)
}

// ── Encryption / decryption ───────────────────────────────────────────────────

export function chachaEncryptChunk(len: i32): i32 {
	if (len <= 0 || len > CHUNK_SIZE) return -1

	let processed: i32 = 0
	while (processed < len) {
		block()

		const remaining = len - processed
		const blockLen  = remaining < 64 ? remaining : 64
		for (let i = 0; i < blockLen; i++) {
			const ks = load<u8>(CHACHA_BLOCK_OFFSET + i)
			const pt = load<u8>(CHUNK_PT_OFFSET + processed + i)
			store<u8>(CHUNK_CT_OFFSET + processed + i, ks ^ pt)
		}

		const ctr = load<u32>(CHACHA_STATE_OFFSET + 48) + 1
		store<u32>(CHACHA_STATE_OFFSET + 48, ctr)
		store<u32>(CHACHA_CTR_OFFSET, ctr)

		processed += blockLen
	}
	return len
}

export function chachaDecryptChunk(len: i32): i32 {
	return chachaEncryptChunk(len)
}

// ── Poly1305 key generation ──────────────────────────────────────────────────
// RFC 8439 §2.6
export function chachaGenPolyKey(): void {
	store<u32>(CHACHA_STATE_OFFSET + 48, 0)
	block()
	memory.copy(POLY_KEY_OFFSET, CHACHA_BLOCK_OFFSET, 32)
}

// ── HChaCha20 subkey derivation ──────────────────────────────────────────────
// IETF draft-irtf-cfrg-xchacha §2.1
// NO initial-state add-back step (key difference from block()).
export function hchacha20(): void {
	const s = CHACHA_STATE_OFFSET

	store<u32>(s +  0, C0)
	store<u32>(s +  4, C1)
	store<u32>(s +  8, C2)
	store<u32>(s + 12, C3)

	for (let i = 0; i < 8; i++)
		store<u32>(s + 16 + i * 4, load<u32>(KEY_OFFSET + i * 4))

	// words 12–15: first 16 bytes of XChaCha20 nonce
	for (let i = 0; i < 4; i++)
		store<u32>(s + 48 + i * 4, load<u32>(XCHACHA_NONCE_OFFSET + i * 4))

	for (let i = 0; i < 10; i++) doubleRound(s)

	// Output words 0–3 and 12–15 — NO add-back
	const out = XCHACHA_SUBKEY_OFFSET
	for (let i = 0; i < 4; i++)
		store<u32>(out + i * 4,       load<u32>(s + i * 4))
	for (let i = 0; i < 4; i++)
		store<u32>(out + 16 + i * 4,  load<u32>(s + 48 + i * 4))
}
