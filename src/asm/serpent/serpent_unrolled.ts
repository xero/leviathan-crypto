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
// src/asm/serpent/serpent_unrolled.ts
//
// AUTO-GENERATED — do not edit by hand.
// To regenerate: bun bench/generate_unrolled.ts > assembly/serpent_unrolled.ts
//
// Fully unrolled Serpent-256 encrypt and decrypt.
// All 32 rounds expanded with hardcoded slot constants to enable
// V8 TurboFan alias analysis to promote working registers from
// WASM linear memory (502 load/stores per block) to CPU registers.
//
// Generated: 2026-02-28T18:36:20.701Z

import {
	BLOCK_PT_OFFSET, BLOCK_CT_OFFSET,
	SUBKEY_OFFSET, WORK_OFFSET,
} from './buffers'

import {
	sb0, sb1, sb2, sb3, sb4, sb5, sb6, sb7,
	si0, si1, si2, si3, si4, si5, si6, si7,
	lk, kl, keyXor,
} from './serpent'

// Working register helpers — identical to those in serpent.ts.
// With all slot indices hardcoded (compile-time constants), every
// rget/rset call resolves to a fixed address in linear memory,
// enabling TurboFan alias analysis and CPU register promotion.
@inline function rget(i: i32): i32 { return load<i32>(WORK_OFFSET + (i << 2)) }
@inline function rset(i: i32, v: i32): void { store<i32>(WORK_OFFSET + (i << 2), v) }

// Fully unrolled block encryption.
// Reads 16 bytes from BLOCK_PT_BUFFER, writes 16 bytes to BLOCK_CT_BUFFER.
export function encryptBlock_unrolled(): void {
	// Load plaintext: bytes reversed, loaded as 4 LE 32-bit words
	// r[0]=bytes[15..12], r[1]=[11..8], r[2]=[7..4], r[3]=[3..0]
	const p = BLOCK_PT_OFFSET
	rset(0, i32(load<u8>(p+15)) | (i32(load<u8>(p+14))<<8) | (i32(load<u8>(p+13))<<16) | (i32(load<u8>(p+12))<<24))
	rset(1, i32(load<u8>(p+11)) | (i32(load<u8>(p+10))<<8) | (i32(load<u8>(p+ 9))<<16) | (i32(load<u8>(p+ 8))<<24))
	rset(2, i32(load<u8>(p+ 7)) | (i32(load<u8>(p+ 6))<<8) | (i32(load<u8>(p+ 5))<<16) | (i32(load<u8>(p+ 4))<<24))
	rset(3, i32(load<u8>(p+ 3)) | (i32(load<u8>(p+ 2))<<8) | (i32(load<u8>(p+ 1))<<16) | (i32(load<u8>(p+ 0))<<24))

	keyXor(0, 1, 2, 3, 0) // K(0)

	// Round 0: sb0, lk→K(1)
	sb0(0, 1, 2, 3, 4)
	lk(2, 1, 3, 0, 4, 1)

	// Round 1: sb1, lk→K(2)
	sb1(2, 1, 3, 0, 4)
	lk(4, 3, 0, 2, 1, 2)

	// Round 2: sb2, lk→K(3)
	sb2(4, 3, 0, 2, 1)
	lk(1, 3, 4, 2, 0, 3)

	// Round 3: sb3, lk→K(4)
	sb3(1, 3, 4, 2, 0)
	lk(2, 0, 3, 1, 4, 4)

	// Round 4: sb4, lk→K(5)
	sb4(2, 0, 3, 1, 4)
	lk(0, 3, 1, 4, 2, 5)

	// Round 5: sb5, lk→K(6)
	sb5(0, 3, 1, 4, 2)
	lk(2, 0, 3, 4, 1, 6)

	// Round 6: sb6, lk→K(7)
	sb6(2, 0, 3, 4, 1)
	lk(3, 1, 0, 4, 2, 7)

	// Round 7: sb7, lk→K(8)
	sb7(3, 1, 0, 4, 2)
	lk(2, 0, 4, 3, 1, 8)

	// Round 8: sb0, lk→K(9)
	sb0(2, 0, 4, 3, 1)
	lk(4, 0, 3, 2, 1, 9)

	// Round 9: sb1, lk→K(10)
	sb1(4, 0, 3, 2, 1)
	lk(1, 3, 2, 4, 0, 10)

	// Round 10: sb2, lk→K(11)
	sb2(1, 3, 2, 4, 0)
	lk(0, 3, 1, 4, 2, 11)

	// Round 11: sb3, lk→K(12)
	sb3(0, 3, 1, 4, 2)
	lk(4, 2, 3, 0, 1, 12)

	// Round 12: sb4, lk→K(13)
	sb4(4, 2, 3, 0, 1)
	lk(2, 3, 0, 1, 4, 13)

	// Round 13: sb5, lk→K(14)
	sb5(2, 3, 0, 1, 4)
	lk(4, 2, 3, 1, 0, 14)

	// Round 14: sb6, lk→K(15)
	sb6(4, 2, 3, 1, 0)
	lk(3, 0, 2, 1, 4, 15)

	// Round 15: sb7, lk→K(16)
	sb7(3, 0, 2, 1, 4)
	lk(4, 2, 1, 3, 0, 16)

	// Round 16: sb0, lk→K(17)
	sb0(4, 2, 1, 3, 0)
	lk(1, 2, 3, 4, 0, 17)

	// Round 17: sb1, lk→K(18)
	sb1(1, 2, 3, 4, 0)
	lk(0, 3, 4, 1, 2, 18)

	// Round 18: sb2, lk→K(19)
	sb2(0, 3, 4, 1, 2)
	lk(2, 3, 0, 1, 4, 19)

	// Round 19: sb3, lk→K(20)
	sb3(2, 3, 0, 1, 4)
	lk(1, 4, 3, 2, 0, 20)

	// Round 20: sb4, lk→K(21)
	sb4(1, 4, 3, 2, 0)
	lk(4, 3, 2, 0, 1, 21)

	// Round 21: sb5, lk→K(22)
	sb5(4, 3, 2, 0, 1)
	lk(1, 4, 3, 0, 2, 22)

	// Round 22: sb6, lk→K(23)
	sb6(1, 4, 3, 0, 2)
	lk(3, 2, 4, 0, 1, 23)

	// Round 23: sb7, lk→K(24)
	sb7(3, 2, 4, 0, 1)
	lk(1, 4, 0, 3, 2, 24)

	// Round 24: sb0, lk→K(25)
	sb0(1, 4, 0, 3, 2)
	lk(0, 4, 3, 1, 2, 25)

	// Round 25: sb1, lk→K(26)
	sb1(0, 4, 3, 1, 2)
	lk(2, 3, 1, 0, 4, 26)

	// Round 26: sb2, lk→K(27)
	sb2(2, 3, 1, 0, 4)
	lk(4, 3, 2, 0, 1, 27)

	// Round 27: sb3, lk→K(28)
	sb3(4, 3, 2, 0, 1)
	lk(0, 1, 3, 4, 2, 28)

	// Round 28: sb4, lk→K(29)
	sb4(0, 1, 3, 4, 2)
	lk(1, 3, 4, 2, 0, 29)

	// Round 29: sb5, lk→K(30)
	sb5(1, 3, 4, 2, 0)
	lk(0, 1, 3, 2, 4, 30)

	// Round 30: sb6, lk→K(31)
	sb6(0, 1, 3, 2, 4)
	lk(3, 4, 1, 2, 0, 31)

	// Round 31 (final — no linear transform):
	sb7(3, 4, 1, 2, 0)

	keyXor(0, 1, 2, 3, 32) // K(32)

	// Store ciphertext big-endian: r[3]→[0..3], r[2]→[4..7], r[1]→[8..11], r[0]→[12..15]
	const c = BLOCK_CT_OFFSET
	let v = rget(3)
	store<u8>(c+ 0,u8(v>>>24)); store<u8>(c+ 1,u8(v>>>16)); store<u8>(c+ 2,u8(v>>>8)); store<u8>(c+ 3,u8(v))
	v = rget(2)
	store<u8>(c+ 4,u8(v>>>24)); store<u8>(c+ 5,u8(v>>>16)); store<u8>(c+ 6,u8(v>>>8)); store<u8>(c+ 7,u8(v))
	v = rget(1)
	store<u8>(c+ 8,u8(v>>>24)); store<u8>(c+ 9,u8(v>>>16)); store<u8>(c+10,u8(v>>>8)); store<u8>(c+11,u8(v))
	v = rget(0)
	store<u8>(c+12,u8(v>>>24)); store<u8>(c+13,u8(v>>>16)); store<u8>(c+14,u8(v>>>8)); store<u8>(c+15,u8(v))
}

// Fully unrolled block decryption.
// Reads 16 bytes from BLOCK_CT_BUFFER, writes 16 bytes to BLOCK_PT_BUFFER.
export function decryptBlock_unrolled(): void {
	// Load ciphertext: same byte-reversal as encrypt
	const c = BLOCK_CT_OFFSET
	rset(0, i32(load<u8>(c+15)) | (i32(load<u8>(c+14))<<8) | (i32(load<u8>(c+13))<<16) | (i32(load<u8>(c+12))<<24))
	rset(1, i32(load<u8>(c+11)) | (i32(load<u8>(c+10))<<8) | (i32(load<u8>(c+ 9))<<16) | (i32(load<u8>(c+ 8))<<24))
	rset(2, i32(load<u8>(c+ 7)) | (i32(load<u8>(c+ 6))<<8) | (i32(load<u8>(c+ 5))<<16) | (i32(load<u8>(c+ 4))<<24))
	rset(3, i32(load<u8>(c+ 3)) | (i32(load<u8>(c+ 2))<<8) | (i32(load<u8>(c+ 1))<<16) | (i32(load<u8>(c+ 0))<<24))

	keyXor(0, 1, 2, 3, 32) // K(32)

	// Round 0: si7, kl→K(31)
	si7(0, 1, 2, 3, 4)
	kl(1, 3, 0, 4, 2, 31)

	// Round 1: si6, kl→K(30)
	si6(1, 3, 0, 4, 2)
	kl(0, 2, 4, 1, 3, 30)

	// Round 2: si5, kl→K(29)
	si5(0, 2, 4, 1, 3)
	kl(2, 3, 0, 4, 1, 29)

	// Round 3: si4, kl→K(28)
	si4(2, 3, 0, 4, 1)
	kl(2, 0, 1, 4, 3, 28)

	// Round 4: si3, kl→K(27)
	si3(2, 0, 1, 4, 3)
	kl(1, 2, 3, 4, 0, 27)

	// Round 5: si2, kl→K(26)
	si2(1, 2, 3, 4, 0)
	kl(2, 0, 4, 3, 1, 26)

	// Round 6: si1, kl→K(25)
	si1(2, 0, 4, 3, 1)
	kl(1, 0, 4, 3, 2, 25)

	// Round 7: si0, kl→K(24)
	si0(1, 0, 4, 3, 2)
	kl(4, 2, 0, 1, 3, 24)

	// Round 8: si7, kl→K(23)
	si7(4, 2, 0, 1, 3)
	kl(2, 1, 4, 3, 0, 23)

	// Round 9: si6, kl→K(22)
	si6(2, 1, 4, 3, 0)
	kl(4, 0, 3, 2, 1, 22)

	// Round 10: si5, kl→K(21)
	si5(4, 0, 3, 2, 1)
	kl(0, 1, 4, 3, 2, 21)

	// Round 11: si4, kl→K(20)
	si4(0, 1, 4, 3, 2)
	kl(0, 4, 2, 3, 1, 20)

	// Round 12: si3, kl→K(19)
	si3(0, 4, 2, 3, 1)
	kl(2, 0, 1, 3, 4, 19)

	// Round 13: si2, kl→K(18)
	si2(2, 0, 1, 3, 4)
	kl(0, 4, 3, 1, 2, 18)

	// Round 14: si1, kl→K(17)
	si1(0, 4, 3, 1, 2)
	kl(2, 4, 3, 1, 0, 17)

	// Round 15: si0, kl→K(16)
	si0(2, 4, 3, 1, 0)
	kl(3, 0, 4, 2, 1, 16)

	// Round 16: si7, kl→K(15)
	si7(3, 0, 4, 2, 1)
	kl(0, 2, 3, 1, 4, 15)

	// Round 17: si6, kl→K(14)
	si6(0, 2, 3, 1, 4)
	kl(3, 4, 1, 0, 2, 14)

	// Round 18: si5, kl→K(13)
	si5(3, 4, 1, 0, 2)
	kl(4, 2, 3, 1, 0, 13)

	// Round 19: si4, kl→K(12)
	si4(4, 2, 3, 1, 0)
	kl(4, 3, 0, 1, 2, 12)

	// Round 20: si3, kl→K(11)
	si3(4, 3, 0, 1, 2)
	kl(0, 4, 2, 1, 3, 11)

	// Round 21: si2, kl→K(10)
	si2(0, 4, 2, 1, 3)
	kl(4, 3, 1, 2, 0, 10)

	// Round 22: si1, kl→K(9)
	si1(4, 3, 1, 2, 0)
	kl(0, 3, 1, 2, 4, 9)

	// Round 23: si0, kl→K(8)
	si0(0, 3, 1, 2, 4)
	kl(1, 4, 3, 0, 2, 8)

	// Round 24: si7, kl→K(7)
	si7(1, 4, 3, 0, 2)
	kl(4, 0, 1, 2, 3, 7)

	// Round 25: si6, kl→K(6)
	si6(4, 0, 1, 2, 3)
	kl(1, 3, 2, 4, 0, 6)

	// Round 26: si5, kl→K(5)
	si5(1, 3, 2, 4, 0)
	kl(3, 0, 1, 2, 4, 5)

	// Round 27: si4, kl→K(4)
	si4(3, 0, 1, 2, 4)
	kl(3, 1, 4, 2, 0, 4)

	// Round 28: si3, kl→K(3)
	si3(3, 1, 4, 2, 0)
	kl(4, 3, 0, 2, 1, 3)

	// Round 29: si2, kl→K(2)
	si2(4, 3, 0, 2, 1)
	kl(3, 1, 2, 0, 4, 2)

	// Round 30: si1, kl→K(1)
	si1(3, 1, 2, 0, 4)
	kl(4, 1, 2, 0, 3, 1)

	// Round 31 (final — no inverse linear transform):
	si0(4, 1, 2, 0, 3)

	// K(0): final key XOR uses slots (2,3,1,4) — CRITICAL: not (0,1,2,3)
	keyXor(2, 3, 1, 4, 0) // K(0)

	// Store plaintext: r[4]→[0..3], r[1]→[4..7], r[3]→[8..11], r[2]→[12..15]
	const p = BLOCK_PT_OFFSET
	let v = rget(4)
	store<u8>(p+ 0,u8(v>>>24)); store<u8>(p+ 1,u8(v>>>16)); store<u8>(p+ 2,u8(v>>>8)); store<u8>(p+ 3,u8(v))
	v = rget(1)
	store<u8>(p+ 4,u8(v>>>24)); store<u8>(p+ 5,u8(v>>>16)); store<u8>(p+ 6,u8(v>>>8)); store<u8>(p+ 7,u8(v))
	v = rget(3)
	store<u8>(p+ 8,u8(v>>>24)); store<u8>(p+ 9,u8(v>>>16)); store<u8>(p+10,u8(v>>>8)); store<u8>(p+11,u8(v))
	v = rget(2)
	store<u8>(p+12,u8(v>>>24)); store<u8>(p+13,u8(v>>>16)); store<u8>(p+14,u8(v>>>8)); store<u8>(p+15,u8(v))
}
