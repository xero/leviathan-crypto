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
// src/asm/serpent/serpent.ts
//
// Serpent-256 block cipher — AssemblyScript port
// Reference: sources/leviathan/src/serpent.ts (TypeScript)
// Spec: Serpent AES submission, Anderson/Biham/Knudsen 1998
//
// Working registers r[0..4] live in WASM linear memory at WORK_OFFSET.
// All slot indices passed to S-boxes/LT/ILT are in {0,1,2,3,4} and are
// always distinct (guaranteed by the EC/DC/KC constant encoding scheme).

import {
	KEY_OFFSET,
	BLOCK_PT_OFFSET, BLOCK_CT_OFFSET,
	NONCE_OFFSET, COUNTER_OFFSET,
	SUBKEY_OFFSET,
	CHUNK_PT_OFFSET, CHUNK_CT_OFFSET,
	CHUNK_SIZE,
	WORK_OFFSET,
	CBC_IV_OFFSET,
	SIMD_WORK_OFFSET,
} from './buffers'

// ── Working register helpers ───────────────────────────────────────────────────
@inline function rget(i: i32): i32 { return load<i32>(WORK_OFFSET + (i << 2)) }
@inline function rset(i: i32, v: i32): void { store<i32>(WORK_OFFSET + (i << 2), v) }

// ── EC/DC/KC constant lookup functions ────────────────────────────────────────
// Each constant encodes a 5-slot permutation: (m%5, m%7, m%11, m%13, m%17).
// All five values are always in {0,1,2,3,4} and are always distinct.

function ec(n: i32): i32 {
	switch (n) {
		case  0: return 44255; case  1: return 61867; case  2: return 45034;
		case  3: return 52496; case  4: return 73087; case  5: return 56255;
		case  6: return 43827; case  7: return 41448; case  8: return 18242;
		case  9: return 1939;  case 10: return 18581; case 11: return 56255;
		case 12: return 64584; case 13: return 31097; case 14: return 26469;
		case 15: return 77728; case 16: return 77639; case 17: return 4216;
		case 18: return 64585; case 19: return 31097; case 20: return 66861;
		case 21: return 78949; case 22: return 58006; case 23: return 59943;
		case 24: return 49676; case 25: return 78950; case 26: return 5512;
		case 27: return 78949; case 28: return 27525; case 29: return 52496;
		case 30: return 18670; case 31: return 76143;
		default: return 0;
	}
}

function dc(n: i32): i32 {
	switch (n) {
		case  0: return 44255; case  1: return 60896; case  2: return 28835;
		case  3: return 1837;  case  4: return 1057;  case  5: return 4216;
		case  6: return 18242; case  7: return 77301; case  8: return 47399;
		case  9: return 53992; case 10: return 1939;  case 11: return 1940;
		case 12: return 66420; case 13: return 39172; case 14: return 78950;
		case 15: return 45917; case 16: return 82383; case 17: return 7450;
		case 18: return 67288; case 19: return 26469; case 20: return 83149;
		case 21: return 57565; case 22: return 66419; case 23: return 47400;
		case 24: return 58006; case 25: return 44254; case 26: return 18581;
		case 27: return 18228; case 28: return 33048; case 29: return 45034;
		case 30: return 66508; case 31: return 7449;
		default: return 0;
	}
}

function kc(n: i32): i32 {
	switch (n) {
		case  0: return 7788;  case  1: return 63716; case  2: return 84032;
		case  3: return 7891;  case  4: return 78949; case  5: return 25146;
		case  6: return 28835; case  7: return 67288; case  8: return 84032;
		case  9: return 40055; case 10: return 7361;  case 11: return 1940;
		case 12: return 77639; case 13: return 27525; case 14: return 24193;
		case 15: return 75702; case 16: return 7361;  case 17: return 35413;
		case 18: return 83150; case 19: return 82383; case 20: return 58619;
		case 21: return 48468; case 22: return 18242; case 23: return 66861;
		case 24: return 83150; case 25: return 69667; case 26: return 7788;
		case 27: return 31552; case 28: return 40054; case 29: return 23222;
		case 30: return 52496; case 31: return 57565; case 32: return 7788;
		case 33: return 63716;
		default: return 0;
	}
}

// ── S-boxes (encryption) ──────────────────────────────────────────────────────
// Boolean circuit implementations — constant-time, no table lookups.
// Each takes 5 slot indices (x0-x4) that index into the working registers.

@inline export function sb0(x0: i32, x1: i32, x2: i32, x3: i32, x4: i32): void {
	rset(x4, rget(x3)); rset(x3, rget(x3) | rget(x0)); rset(x0, rget(x0) ^ rget(x4));
	rset(x4, rget(x4) ^ rget(x2)); rset(x4, ~rget(x4)); rset(x3, rget(x3) ^ rget(x1));
	rset(x1, rget(x1) & rget(x0)); rset(x1, rget(x1) ^ rget(x4)); rset(x2, rget(x2) ^ rget(x0));
	rset(x0, rget(x0) ^ rget(x3)); rset(x4, rget(x4) | rget(x0)); rset(x0, rget(x0) ^ rget(x2));
	rset(x2, rget(x2) & rget(x1)); rset(x3, rget(x3) ^ rget(x2)); rset(x1, ~rget(x1));
	rset(x2, rget(x2) ^ rget(x4)); rset(x1, rget(x1) ^ rget(x2));
}

@inline export function sb1(x0: i32, x1: i32, x2: i32, x3: i32, x4: i32): void {
	rset(x4, rget(x1)); rset(x1, rget(x1) ^ rget(x0)); rset(x0, rget(x0) ^ rget(x3));
	rset(x3, ~rget(x3)); rset(x4, rget(x4) & rget(x1)); rset(x0, rget(x0) | rget(x1));
	rset(x3, rget(x3) ^ rget(x2)); rset(x0, rget(x0) ^ rget(x3)); rset(x1, rget(x1) ^ rget(x3));
	rset(x3, rget(x3) ^ rget(x4)); rset(x1, rget(x1) | rget(x4)); rset(x4, rget(x4) ^ rget(x2));
	rset(x2, rget(x2) & rget(x0)); rset(x2, rget(x2) ^ rget(x1)); rset(x1, rget(x1) | rget(x0));
	rset(x0, ~rget(x0)); rset(x0, rget(x0) ^ rget(x2)); rset(x4, rget(x4) ^ rget(x1));
}

@inline export function sb2(x0: i32, x1: i32, x2: i32, x3: i32, x4: i32): void {
	rset(x3, ~rget(x3)); rset(x1, rget(x1) ^ rget(x0)); rset(x4, rget(x0));
	rset(x0, rget(x0) & rget(x2)); rset(x0, rget(x0) ^ rget(x3)); rset(x3, rget(x3) | rget(x4));
	rset(x2, rget(x2) ^ rget(x1)); rset(x3, rget(x3) ^ rget(x1)); rset(x1, rget(x1) & rget(x0));
	rset(x0, rget(x0) ^ rget(x2)); rset(x2, rget(x2) & rget(x3)); rset(x3, rget(x3) | rget(x1));
	rset(x0, ~rget(x0)); rset(x3, rget(x3) ^ rget(x0)); rset(x4, rget(x4) ^ rget(x0));
	rset(x0, rget(x0) ^ rget(x2)); rset(x1, rget(x1) | rget(x2));
}

@inline export function sb3(x0: i32, x1: i32, x2: i32, x3: i32, x4: i32): void {
	rset(x4, rget(x1)); rset(x1, rget(x1) ^ rget(x3)); rset(x3, rget(x3) | rget(x0));
	rset(x4, rget(x4) & rget(x0)); rset(x0, rget(x0) ^ rget(x2)); rset(x2, rget(x2) ^ rget(x1));
	rset(x1, rget(x1) & rget(x3)); rset(x2, rget(x2) ^ rget(x3)); rset(x0, rget(x0) | rget(x4));
	rset(x4, rget(x4) ^ rget(x3)); rset(x1, rget(x1) ^ rget(x0)); rset(x0, rget(x0) & rget(x3));
	rset(x3, rget(x3) & rget(x4)); rset(x3, rget(x3) ^ rget(x2)); rset(x4, rget(x4) | rget(x1));
	rset(x2, rget(x2) & rget(x1)); rset(x4, rget(x4) ^ rget(x3)); rset(x0, rget(x0) ^ rget(x3));
	rset(x3, rget(x3) ^ rget(x2));
}

@inline export function sb4(x0: i32, x1: i32, x2: i32, x3: i32, x4: i32): void {
	rset(x4, rget(x3)); rset(x3, rget(x3) & rget(x0)); rset(x0, rget(x0) ^ rget(x4));
	rset(x3, rget(x3) ^ rget(x2)); rset(x2, rget(x2) | rget(x4)); rset(x0, rget(x0) ^ rget(x1));
	rset(x4, rget(x4) ^ rget(x3)); rset(x2, rget(x2) | rget(x0)); rset(x2, rget(x2) ^ rget(x1));
	rset(x1, rget(x1) & rget(x0)); rset(x1, rget(x1) ^ rget(x4)); rset(x4, rget(x4) & rget(x2));
	rset(x2, rget(x2) ^ rget(x3)); rset(x4, rget(x4) ^ rget(x0)); rset(x3, rget(x3) | rget(x1));
	rset(x1, ~rget(x1)); rset(x3, rget(x3) ^ rget(x0));
}

@inline export function sb5(x0: i32, x1: i32, x2: i32, x3: i32, x4: i32): void {
	rset(x4, rget(x1)); rset(x1, rget(x1) | rget(x0)); rset(x2, rget(x2) ^ rget(x1));
	rset(x3, ~rget(x3)); rset(x4, rget(x4) ^ rget(x0)); rset(x0, rget(x0) ^ rget(x2));
	rset(x1, rget(x1) & rget(x4)); rset(x4, rget(x4) | rget(x3)); rset(x4, rget(x4) ^ rget(x0));
	rset(x0, rget(x0) & rget(x3)); rset(x1, rget(x1) ^ rget(x3)); rset(x3, rget(x3) ^ rget(x2));
	rset(x0, rget(x0) ^ rget(x1)); rset(x2, rget(x2) & rget(x4)); rset(x1, rget(x1) ^ rget(x2));
	rset(x2, rget(x2) & rget(x0)); rset(x3, rget(x3) ^ rget(x2));
}

@inline export function sb6(x0: i32, x1: i32, x2: i32, x3: i32, x4: i32): void {
	rset(x4, rget(x1)); rset(x3, rget(x3) ^ rget(x0)); rset(x1, rget(x1) ^ rget(x2));
	rset(x2, rget(x2) ^ rget(x0)); rset(x0, rget(x0) & rget(x3)); rset(x1, rget(x1) | rget(x3));
	rset(x4, ~rget(x4)); rset(x0, rget(x0) ^ rget(x1)); rset(x1, rget(x1) ^ rget(x2));
	rset(x3, rget(x3) ^ rget(x4)); rset(x4, rget(x4) ^ rget(x0)); rset(x2, rget(x2) & rget(x0));
	rset(x4, rget(x4) ^ rget(x1)); rset(x2, rget(x2) ^ rget(x3)); rset(x3, rget(x3) & rget(x1));
	rset(x3, rget(x3) ^ rget(x0)); rset(x1, rget(x1) ^ rget(x2));
}

@inline export function sb7(x0: i32, x1: i32, x2: i32, x3: i32, x4: i32): void {
	rset(x1, ~rget(x1)); rset(x4, rget(x1)); rset(x0, ~rget(x0)); rset(x1, rget(x1) & rget(x2));
	rset(x1, rget(x1) ^ rget(x3)); rset(x3, rget(x3) | rget(x4)); rset(x4, rget(x4) ^ rget(x2));
	rset(x2, rget(x2) ^ rget(x3)); rset(x3, rget(x3) ^ rget(x0)); rset(x0, rget(x0) | rget(x1));
	rset(x2, rget(x2) & rget(x0)); rset(x0, rget(x0) ^ rget(x4)); rset(x4, rget(x4) ^ rget(x3));
	rset(x3, rget(x3) & rget(x0)); rset(x4, rget(x4) ^ rget(x1)); rset(x2, rget(x2) ^ rget(x4));
	rset(x3, rget(x3) ^ rget(x1)); rset(x4, rget(x4) | rget(x0)); rset(x4, rget(x4) ^ rget(x1));
}

// ── Inverse S-boxes (decryption) ──────────────────────────────────────────────

@inline export function si0(x0: i32, x1: i32, x2: i32, x3: i32, x4: i32): void {
	rset(x4, rget(x3)); rset(x1, rget(x1) ^ rget(x0)); rset(x3, rget(x3) | rget(x1));
	rset(x4, rget(x4) ^ rget(x1)); rset(x0, ~rget(x0)); rset(x2, rget(x2) ^ rget(x3));
	rset(x3, rget(x3) ^ rget(x0)); rset(x0, rget(x0) & rget(x1)); rset(x0, rget(x0) ^ rget(x2));
	rset(x2, rget(x2) & rget(x3)); rset(x3, rget(x3) ^ rget(x4)); rset(x2, rget(x2) ^ rget(x3));
	rset(x1, rget(x1) ^ rget(x3)); rset(x3, rget(x3) & rget(x0)); rset(x1, rget(x1) ^ rget(x0));
	rset(x0, rget(x0) ^ rget(x2)); rset(x4, rget(x4) ^ rget(x3));
}

@inline export function si1(x0: i32, x1: i32, x2: i32, x3: i32, x4: i32): void {
	rset(x1, rget(x1) ^ rget(x3)); rset(x4, rget(x0)); rset(x0, rget(x0) ^ rget(x2));
	rset(x2, ~rget(x2)); rset(x4, rget(x4) | rget(x1)); rset(x4, rget(x4) ^ rget(x3));
	rset(x3, rget(x3) & rget(x1)); rset(x1, rget(x1) ^ rget(x2)); rset(x2, rget(x2) & rget(x4));
	rset(x4, rget(x4) ^ rget(x1)); rset(x1, rget(x1) | rget(x3)); rset(x3, rget(x3) ^ rget(x0));
	rset(x2, rget(x2) ^ rget(x0)); rset(x0, rget(x0) | rget(x4)); rset(x2, rget(x2) ^ rget(x4));
	rset(x1, rget(x1) ^ rget(x0)); rset(x4, rget(x4) ^ rget(x1));
}

@inline export function si2(x0: i32, x1: i32, x2: i32, x3: i32, x4: i32): void {
	rset(x2, rget(x2) ^ rget(x1)); rset(x4, rget(x3)); rset(x3, ~rget(x3));
	rset(x3, rget(x3) | rget(x2)); rset(x2, rget(x2) ^ rget(x4)); rset(x4, rget(x4) ^ rget(x0));
	rset(x3, rget(x3) ^ rget(x1)); rset(x1, rget(x1) | rget(x2)); rset(x2, rget(x2) ^ rget(x0));
	rset(x1, rget(x1) ^ rget(x4)); rset(x4, rget(x4) | rget(x3)); rset(x2, rget(x2) ^ rget(x3));
	rset(x4, rget(x4) ^ rget(x2)); rset(x2, rget(x2) & rget(x1)); rset(x2, rget(x2) ^ rget(x3));
	rset(x3, rget(x3) ^ rget(x4)); rset(x4, rget(x4) ^ rget(x0));
}

@inline export function si3(x0: i32, x1: i32, x2: i32, x3: i32, x4: i32): void {
	rset(x2, rget(x2) ^ rget(x1)); rset(x4, rget(x1)); rset(x1, rget(x1) & rget(x2));
	rset(x1, rget(x1) ^ rget(x0)); rset(x0, rget(x0) | rget(x4)); rset(x4, rget(x4) ^ rget(x3));
	rset(x0, rget(x0) ^ rget(x3)); rset(x3, rget(x3) | rget(x1)); rset(x1, rget(x1) ^ rget(x2));
	rset(x1, rget(x1) ^ rget(x3)); rset(x0, rget(x0) ^ rget(x2)); rset(x2, rget(x2) ^ rget(x3));
	rset(x3, rget(x3) & rget(x1)); rset(x1, rget(x1) ^ rget(x0)); rset(x0, rget(x0) & rget(x2));
	rset(x4, rget(x4) ^ rget(x3)); rset(x3, rget(x3) ^ rget(x0)); rset(x0, rget(x0) ^ rget(x1));
}

@inline export function si4(x0: i32, x1: i32, x2: i32, x3: i32, x4: i32): void {
	rset(x2, rget(x2) ^ rget(x3)); rset(x4, rget(x0)); rset(x0, rget(x0) & rget(x1));
	rset(x0, rget(x0) ^ rget(x2)); rset(x2, rget(x2) | rget(x3)); rset(x4, ~rget(x4));
	rset(x1, rget(x1) ^ rget(x0)); rset(x0, rget(x0) ^ rget(x2)); rset(x2, rget(x2) & rget(x4));
	rset(x2, rget(x2) ^ rget(x0)); rset(x0, rget(x0) | rget(x4)); rset(x0, rget(x0) ^ rget(x3));
	rset(x3, rget(x3) & rget(x2)); rset(x4, rget(x4) ^ rget(x3)); rset(x3, rget(x3) ^ rget(x1));
	rset(x1, rget(x1) & rget(x0)); rset(x4, rget(x4) ^ rget(x1)); rset(x0, rget(x0) ^ rget(x3));
}

@inline export function si5(x0: i32, x1: i32, x2: i32, x3: i32, x4: i32): void {
	rset(x4, rget(x1)); rset(x1, rget(x1) | rget(x2)); rset(x2, rget(x2) ^ rget(x4));
	rset(x1, rget(x1) ^ rget(x3)); rset(x3, rget(x3) & rget(x4)); rset(x2, rget(x2) ^ rget(x3));
	rset(x3, rget(x3) | rget(x0)); rset(x0, ~rget(x0)); rset(x3, rget(x3) ^ rget(x2));
	rset(x2, rget(x2) | rget(x0)); rset(x4, rget(x4) ^ rget(x1)); rset(x2, rget(x2) ^ rget(x4));
	rset(x4, rget(x4) & rget(x0)); rset(x0, rget(x0) ^ rget(x1)); rset(x1, rget(x1) ^ rget(x3));
	rset(x0, rget(x0) & rget(x2)); rset(x2, rget(x2) ^ rget(x3)); rset(x0, rget(x0) ^ rget(x2));
	rset(x2, rget(x2) ^ rget(x4)); rset(x4, rget(x4) ^ rget(x3));
}

@inline export function si6(x0: i32, x1: i32, x2: i32, x3: i32, x4: i32): void {
	rset(x0, rget(x0) ^ rget(x2)); rset(x4, rget(x0)); rset(x0, rget(x0) & rget(x3));
	rset(x2, rget(x2) ^ rget(x3)); rset(x0, rget(x0) ^ rget(x2)); rset(x3, rget(x3) ^ rget(x1));
	rset(x2, rget(x2) | rget(x4)); rset(x2, rget(x2) ^ rget(x3)); rset(x3, rget(x3) & rget(x0));
	rset(x0, ~rget(x0)); rset(x3, rget(x3) ^ rget(x1)); rset(x1, rget(x1) & rget(x2));
	rset(x4, rget(x4) ^ rget(x0)); rset(x3, rget(x3) ^ rget(x4)); rset(x4, rget(x4) ^ rget(x2));
	rset(x0, rget(x0) ^ rget(x1)); rset(x2, rget(x2) ^ rget(x0));
}

@inline export function si7(x0: i32, x1: i32, x2: i32, x3: i32, x4: i32): void {
	rset(x4, rget(x3)); rset(x3, rget(x3) & rget(x0)); rset(x0, rget(x0) ^ rget(x2));
	rset(x2, rget(x2) | rget(x4)); rset(x4, rget(x4) ^ rget(x1)); rset(x0, ~rget(x0));
	rset(x1, rget(x1) | rget(x3)); rset(x4, rget(x4) ^ rget(x0)); rset(x0, rget(x0) & rget(x2));
	rset(x0, rget(x0) ^ rget(x1)); rset(x1, rget(x1) & rget(x2)); rset(x3, rget(x3) ^ rget(x2));
	rset(x4, rget(x4) ^ rget(x3)); rset(x2, rget(x2) & rget(x3)); rset(x3, rget(x3) | rget(x0));
	rset(x1, rget(x1) ^ rget(x4)); rset(x3, rget(x3) ^ rget(x4)); rset(x4, rget(x4) & rget(x0));
	rset(x4, rget(x4) ^ rget(x2));
}

// ── S-box dispatch ────────────────────────────────────────────────────────────
@inline function applyS(idx: i32, x0: i32, x1: i32, x2: i32, x3: i32, x4: i32): void {
	switch (idx) {
		case 0: sb0(x0, x1, x2, x3, x4); break;
		case 1: sb1(x0, x1, x2, x3, x4); break;
		case 2: sb2(x0, x1, x2, x3, x4); break;
		case 3: sb3(x0, x1, x2, x3, x4); break;
		case 4: sb4(x0, x1, x2, x3, x4); break;
		case 5: sb5(x0, x1, x2, x3, x4); break;
		case 6: sb6(x0, x1, x2, x3, x4); break;
		case 7: sb7(x0, x1, x2, x3, x4); break;
	}
}

@inline function applySI(idx: i32, x0: i32, x1: i32, x2: i32, x3: i32, x4: i32): void {
	switch (idx) {
		case 0: si0(x0, x1, x2, x3, x4); break;
		case 1: si1(x0, x1, x2, x3, x4); break;
		case 2: si2(x0, x1, x2, x3, x4); break;
		case 3: si3(x0, x1, x2, x3, x4); break;
		case 4: si4(x0, x1, x2, x3, x4); break;
		case 5: si5(x0, x1, x2, x3, x4); break;
		case 6: si6(x0, x1, x2, x3, x4); break;
		case 7: si7(x0, x1, x2, x3, x4); break;
	}
}

// ── Key XOR (K function) ──────────────────────────────────────────────────────
// r[a,b,c,d] ^= key[4i+0..3]
@inline export function keyXor(a: i32, b: i32, c: i32, d: i32, i: i32): void {
	rset(a, rget(a) ^ load<i32>(SUBKEY_OFFSET + (4 * i + 0) * 4))
	rset(b, rget(b) ^ load<i32>(SUBKEY_OFFSET + (4 * i + 1) * 4))
	rset(c, rget(c) ^ load<i32>(SUBKEY_OFFSET + (4 * i + 2) * 4))
	rset(d, rget(d) ^ load<i32>(SUBKEY_OFFSET + (4 * i + 3) * 4))
}

// ── Linear transform + key XOR (LK function for encryption) ──────────────────
@inline export function lk(a: i32, b: i32, c: i32, d: i32, e: i32, i: i32): void {
	rset(a, rotl<i32>(rget(a), 13))
	rset(c, rotl<i32>(rget(c), 3))
	rset(b, rget(b) ^ rget(a))
	rset(e, rget(a) << 3)
	rset(d, rget(d) ^ rget(c))
	rset(b, rget(b) ^ rget(c))
	rset(b, rotl<i32>(rget(b), 1))
	rset(d, rget(d) ^ rget(e))
	rset(d, rotl<i32>(rget(d), 7))
	rset(e, rget(b))
	rset(a, rget(a) ^ rget(b))
	rset(e, rget(e) << 7)
	rset(c, rget(c) ^ rget(d))
	rset(a, rget(a) ^ rget(d))
	rset(c, rget(c) ^ rget(e))
	rset(d, rget(d) ^ load<i32>(SUBKEY_OFFSET + (4 * i + 3) * 4))
	rset(b, rget(b) ^ load<i32>(SUBKEY_OFFSET + (4 * i + 1) * 4))
	rset(a, rotl<i32>(rget(a), 5))
	rset(c, rotl<i32>(rget(c), 22))
	rset(a, rget(a) ^ load<i32>(SUBKEY_OFFSET + (4 * i + 0) * 4))
	rset(c, rget(c) ^ load<i32>(SUBKEY_OFFSET + (4 * i + 2) * 4))
}

// ── Inverse key XOR + inverse linear transform (KL for decryption) ────────────
@inline export function kl(a: i32, b: i32, c: i32, d: i32, e: i32, i: i32): void {
	rset(a, rget(a) ^ load<i32>(SUBKEY_OFFSET + (4 * i + 0) * 4))
	rset(b, rget(b) ^ load<i32>(SUBKEY_OFFSET + (4 * i + 1) * 4))
	rset(c, rget(c) ^ load<i32>(SUBKEY_OFFSET + (4 * i + 2) * 4))
	rset(d, rget(d) ^ load<i32>(SUBKEY_OFFSET + (4 * i + 3) * 4))
	rset(a, rotl<i32>(rget(a), 27))
	rset(c, rotl<i32>(rget(c), 10))
	rset(e, rget(b))
	rset(c, rget(c) ^ rget(d))
	rset(a, rget(a) ^ rget(d))
	rset(e, rget(e) << 7)
	rset(a, rget(a) ^ rget(b))
	rset(b, rotl<i32>(rget(b), 31))
	rset(c, rget(c) ^ rget(e))
	rset(d, rotl<i32>(rget(d), 25))
	rset(e, rget(a) << 3)
	rset(b, rget(b) ^ rget(a))
	rset(d, rget(d) ^ rget(e))
	rset(a, rotl<i32>(rget(a), 19))
	rset(b, rget(b) ^ rget(c))
	rset(d, rget(d) ^ rget(c))
	rset(c, rotl<i32>(rget(c), 29))
}

// ── Key schedule helpers ──────────────────────────────────────────────────────

@inline function keyIt(a: i32, b: i32, c: i32, d: i32, i: i32): void {
	const v = rotl<i32>(
		load<i32>(SUBKEY_OFFSET + a * 4) ^ rget(b) ^ rget(c) ^ rget(d) ^ 0x9e3779b9 ^ i,
		11
	)
	store<i32>(SUBKEY_OFFSET + i * 4, v)
	rset(b, v)
}

@inline function keyLoad(a: i32, b: i32, c: i32, d: i32, i: i32): void {
	rset(a, load<i32>(SUBKEY_OFFSET + (i + 0) * 4))
	rset(b, load<i32>(SUBKEY_OFFSET + (i + 1) * 4))
	rset(c, load<i32>(SUBKEY_OFFSET + (i + 2) * 4))
	rset(d, load<i32>(SUBKEY_OFFSET + (i + 3) * 4))
}

@inline function keyStore(a: i32, b: i32, c: i32, d: i32, i: i32): void {
	store<i32>(SUBKEY_OFFSET + (i + 0) * 4, rget(a))
	store<i32>(SUBKEY_OFFSET + (i + 1) * 4, rget(b))
	store<i32>(SUBKEY_OFFSET + (i + 2) * 4, rget(c))
	store<i32>(SUBKEY_OFFSET + (i + 3) * 4, rget(d))
}

// ── Key schedule ──────────────────────────────────────────────────────────────
// Reads keyLen bytes from KEY_BUFFER, expands to 33 × 4 subkeys in SUBKEY_BUFFER.
// Returns 0 on success, -1 if keyLen is invalid.

export function loadKey(keyLen: i32): i32 {
	if (keyLen !== 16 && keyLen !== 24 && keyLen !== 32) return -1

	// Zero the 132-word subkey buffer
	memory.fill(SUBKEY_OFFSET, 0, 132 * 4)

	// Set padding bit at position keyLen (before byte reversal, as per reference)
	store<i32>(SUBKEY_OFFSET + keyLen * 4, 1)

	// Reverse-copy key bytes: key[i] = input_byte[keyLen-i-1]
	// Each element stores 1 byte value as i32 (like the TS Uint32Array usage)
	for (let k = 0; k < keyLen; k++) {
		store<i32>(SUBKEY_OFFSET + k * 4, i32(load<u8>(KEY_OFFSET + keyLen - k - 1)))
	}

	// Repack 8 groups of 4 byte-valued i32s into 8 little-endian uint32 words
	for (let k = 0; k < 8; k++) {
		const b0 = load<i32>(SUBKEY_OFFSET + (4 * k + 0) * 4) & 0xff
		const b1 = load<i32>(SUBKEY_OFFSET + (4 * k + 1) * 4) & 0xff
		const b2 = load<i32>(SUBKEY_OFFSET + (4 * k + 2) * 4) & 0xff
		const b3 = load<i32>(SUBKEY_OFFSET + (4 * k + 3) * 4) & 0xff
		store<i32>(SUBKEY_OFFSET + k * 4, b0 | (b1 << 8) | (b2 << 16) | (b3 << 24))
	}

	// Initialize 5 working registers from key[3..7]
	rset(0, load<i32>(SUBKEY_OFFSET + 3 * 4))
	rset(1, load<i32>(SUBKEY_OFFSET + 4 * 4))
	rset(2, load<i32>(SUBKEY_OFFSET + 5 * 4))
	rset(3, load<i32>(SUBKEY_OFFSET + 6 * 4))
	rset(4, load<i32>(SUBKEY_OFFSET + 7 * 4))

	// keyIt prekey expansion — fills key[0..131]
	// Mirrors the reference JS: while(keyIt(j++,..,i++), keyIt(j++,..,i++), i<132) { 3 more }
	let ii: i32 = 0, jj: i32 = 0
	while (true) {
		const ja = jj; jj++; keyIt(ja, 0, 4, 2, ii); ii++
		const jb = jj; jj++; keyIt(jb, 1, 0, 3, ii); ii++
		if (ii >= 132) break
		const jc = jj; jj++; keyIt(jc, 2, 1, 4, ii); ii++
		if (ii === 8) jj = 0
		const jd = jj; jj++; keyIt(jd, 3, 2, 0, ii); ii++
		const je = jj; jj++; keyIt(je, 4, 3, 1, ii); ii++
	}

	// Round key derivation: apply S-boxes and store 33 subkeys (K32 down to K0)
	let ri: i32 = 128, rj: i32 = 3, n: i32 = 0
	while (true) {
		let m = kc(n); n++
		applyS(rj % 8, m % 5, m % 7, m % 11, m % 13, m % 17)
		rj++
		m = kc(n)  // same n, not incremented
		keyStore(m % 5, m % 7, m % 11, m % 13, ri)
		if (ri <= 0) break
		ri -= 4
		keyLoad(m % 5, m % 7, m % 11, m % 13, ri)
	}

	return 0
}

// ── Block encryption ──────────────────────────────────────────────────────────
// Reads 16 bytes from BLOCK_PT_BUFFER, writes 16 bytes to BLOCK_CT_BUFFER.
// loadKey() must be called first.

export function encryptBlock(): void {
	// Load plaintext: reverse bytes then read as 4 little-endian 32-bit words
	// blk = reversed pt, then r[k] = getW(blk, k*4) = LE load from blk[k*4..k*4+3]
	// Equivalent: r[0]=pt as LE from bytes[15..12], r[1]=bytes[11..8], etc.
	const p = BLOCK_PT_OFFSET
	rset(0, i32(load<u8>(p + 15)) | (i32(load<u8>(p + 14)) << 8) | (i32(load<u8>(p + 13)) << 16) | (i32(load<u8>(p + 12)) << 24))
	rset(1, i32(load<u8>(p + 11)) | (i32(load<u8>(p + 10)) << 8) | (i32(load<u8>(p +  9)) << 16) | (i32(load<u8>(p +  8)) << 24))
	rset(2, i32(load<u8>(p +  7)) | (i32(load<u8>(p +  6)) << 8) | (i32(load<u8>(p +  5)) << 16) | (i32(load<u8>(p +  4)) << 24))
	rset(3, i32(load<u8>(p +  3)) | (i32(load<u8>(p +  2)) << 8) | (i32(load<u8>(p +  1)) << 16) | (i32(load<u8>(p +  0)) << 24))

	// K(0): XOR initial subkey
	keyXor(0, 1, 2, 3, 0)

	// 32 rounds: S-box → linear transform + key XOR
	let n: i32 = 0
	let m = ec(0)
	while (true) {
		applyS(n % 8, m % 5, m % 7, m % 11, m % 13, m % 17)
		if (n >= 31) break
		n++; m = ec(n)
		lk(m % 5, m % 7, m % 11, m % 13, m % 17, n)
	}

	// K(32): XOR final subkey
	keyXor(0, 1, 2, 3, 32)

	// Store ciphertext big-endian: ct[0..3]=r[3], ct[4..7]=r[2], ct[8..11]=r[1], ct[12..15]=r[0]
	const c = BLOCK_CT_OFFSET
	let v = rget(3)
	store<u8>(c + 0, u8(v >>> 24)); store<u8>(c + 1, u8(v >>> 16)); store<u8>(c + 2, u8(v >>> 8)); store<u8>(c + 3, u8(v))
	v = rget(2)
	store<u8>(c + 4, u8(v >>> 24)); store<u8>(c + 5, u8(v >>> 16)); store<u8>(c + 6, u8(v >>> 8)); store<u8>(c + 7, u8(v))
	v = rget(1)
	store<u8>(c + 8, u8(v >>> 24)); store<u8>(c + 9, u8(v >>> 16)); store<u8>(c + 10, u8(v >>> 8)); store<u8>(c + 11, u8(v))
	v = rget(0)
	store<u8>(c + 12, u8(v >>> 24)); store<u8>(c + 13, u8(v >>> 16)); store<u8>(c + 14, u8(v >>> 8)); store<u8>(c + 15, u8(v))
}

// ── Block decryption ──────────────────────────────────────────────────────────
// Reads 16 bytes from BLOCK_CT_BUFFER, writes 16 bytes to BLOCK_PT_BUFFER.
// loadKey() must be called first.

export function decryptBlock(): void {
	// Load ciphertext (same byte-reversal as encrypt)
	const c = BLOCK_CT_OFFSET
	rset(0, i32(load<u8>(c + 15)) | (i32(load<u8>(c + 14)) << 8) | (i32(load<u8>(c + 13)) << 16) | (i32(load<u8>(c + 12)) << 24))
	rset(1, i32(load<u8>(c + 11)) | (i32(load<u8>(c + 10)) << 8) | (i32(load<u8>(c +  9)) << 16) | (i32(load<u8>(c +  8)) << 24))
	rset(2, i32(load<u8>(c +  7)) | (i32(load<u8>(c +  6)) << 8) | (i32(load<u8>(c +  5)) << 16) | (i32(load<u8>(c +  4)) << 24))
	rset(3, i32(load<u8>(c +  3)) | (i32(load<u8>(c +  2)) << 8) | (i32(load<u8>(c +  1)) << 16) | (i32(load<u8>(c +  0)) << 24))

	// K(32): XOR final subkey
	keyXor(0, 1, 2, 3, 32)

	// 32 inverse rounds: inverse S-box → inverse linear transform + key XOR
	let n: i32 = 0
	let m = dc(0)
	while (true) {
		applySI(7 - (n % 8), m % 5, m % 7, m % 11, m % 13, m % 17)
		if (n >= 31) break
		n++; m = dc(n)
		kl(m % 5, m % 7, m % 11, m % 13, m % 17, 32 - n)
	}

	// K(0): final key XOR for decryption uses slots (2,3,1,4)
	keyXor(2, 3, 1, 4, 0)

	// Store plaintext: pt[0..3]=r[4], pt[4..7]=r[1], pt[8..11]=r[3], pt[12..15]=r[2]
	const p = BLOCK_PT_OFFSET
	let v = rget(4)
	store<u8>(p + 0, u8(v >>> 24)); store<u8>(p + 1, u8(v >>> 16)); store<u8>(p + 2, u8(v >>> 8)); store<u8>(p + 3, u8(v))
	v = rget(1)
	store<u8>(p + 4, u8(v >>> 24)); store<u8>(p + 5, u8(v >>> 16)); store<u8>(p + 6, u8(v >>> 8)); store<u8>(p + 7, u8(v))
	v = rget(3)
	store<u8>(p + 8, u8(v >>> 24)); store<u8>(p + 9, u8(v >>> 16)); store<u8>(p + 10, u8(v >>> 8)); store<u8>(p + 11, u8(v))
	v = rget(2)
	store<u8>(p + 12, u8(v >>> 24)); store<u8>(p + 13, u8(v >>> 16)); store<u8>(p + 14, u8(v >>> 8)); store<u8>(p + 15, u8(v))
}

// ── wipeBuffers ───────────────────────────────────────────────────────────────
// Zero all sensitive Serpent module data. Call after use.

export function wipeBuffers(): void {
	memory.fill(KEY_OFFSET,      0, 32)
	memory.fill(BLOCK_PT_OFFSET, 0, 16)
	memory.fill(BLOCK_CT_OFFSET, 0, 16)
	memory.fill(NONCE_OFFSET,    0, 16)
	memory.fill(COUNTER_OFFSET,  0, 16)
	memory.fill(SUBKEY_OFFSET,   0, 528)   // key material — must be zeroed
	memory.fill(WORK_OFFSET,     0, 20)    // working registers
	memory.fill(CHUNK_PT_OFFSET, 0, CHUNK_SIZE)
	memory.fill(CHUNK_CT_OFFSET, 0, CHUNK_SIZE)
	memory.fill(CBC_IV_OFFSET,   0, 16)
	memory.fill(SIMD_WORK_OFFSET, 0, 80)   // 5 × v128
}
