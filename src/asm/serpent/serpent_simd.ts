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
// src/asm/serpent/serpent_simd.ts
//
// AUTO-GENERATED — do not edit by hand.
// To regenerate: bun scripts/generate_simd.ts > src/asm/serpent/serpent_simd.ts
//
// SIMD-accelerated Serpent-256 encrypt and decrypt (4 blocks per call).
// Each v128 register holds 4 × i32 lanes; lane[k] = word from block k.
// S-box gate logic derived from serpent.ts; rotation amounts from the spec.
//
// Generated: 2026-03-27T18:46:28.383Z

import { SUBKEY_OFFSET, SIMD_WORK_OFFSET } from './buffers'

// v128 working register helpers — 5 × v128 at SIMD_WORK_OFFSET, 16-byte stride
@inline function rget_v(i: i32): v128 { return v128.load(SIMD_WORK_OFFSET + (i << 4)) }
@inline function rset_v(i: i32, v: v128): void { v128.store(SIMD_WORK_OFFSET + (i << 4), v) }

// ── Forward S-boxes (v128) ──────────────────────────────────────────────────

@inline function sb0_v(x0: i32, x1: i32, x2: i32, x3: i32, x4: i32): void {
	rset_v(x4, rget_v(x3)); rset_v(x3, v128.or(rget_v(x3), rget_v(x0))); rset_v(x0, v128.xor(rget_v(x0), rget_v(x4)));
	rset_v(x4, v128.xor(rget_v(x4), rget_v(x2))); rset_v(x4, v128.not(rget_v(x4))); rset_v(x3, v128.xor(rget_v(x3), rget_v(x1)));
	rset_v(x1, v128.and(rget_v(x1), rget_v(x0))); rset_v(x1, v128.xor(rget_v(x1), rget_v(x4))); rset_v(x2, v128.xor(rget_v(x2), rget_v(x0)));
	rset_v(x0, v128.xor(rget_v(x0), rget_v(x3))); rset_v(x4, v128.or(rget_v(x4), rget_v(x0))); rset_v(x0, v128.xor(rget_v(x0), rget_v(x2)));
	rset_v(x2, v128.and(rget_v(x2), rget_v(x1))); rset_v(x3, v128.xor(rget_v(x3), rget_v(x2))); rset_v(x1, v128.not(rget_v(x1)));
	rset_v(x2, v128.xor(rget_v(x2), rget_v(x4))); rset_v(x1, v128.xor(rget_v(x1), rget_v(x2)));
}

@inline function sb1_v(x0: i32, x1: i32, x2: i32, x3: i32, x4: i32): void {
	rset_v(x4, rget_v(x1)); rset_v(x1, v128.xor(rget_v(x1), rget_v(x0))); rset_v(x0, v128.xor(rget_v(x0), rget_v(x3)));
	rset_v(x3, v128.not(rget_v(x3))); rset_v(x4, v128.and(rget_v(x4), rget_v(x1))); rset_v(x0, v128.or(rget_v(x0), rget_v(x1)));
	rset_v(x3, v128.xor(rget_v(x3), rget_v(x2))); rset_v(x0, v128.xor(rget_v(x0), rget_v(x3))); rset_v(x1, v128.xor(rget_v(x1), rget_v(x3)));
	rset_v(x3, v128.xor(rget_v(x3), rget_v(x4))); rset_v(x1, v128.or(rget_v(x1), rget_v(x4))); rset_v(x4, v128.xor(rget_v(x4), rget_v(x2)));
	rset_v(x2, v128.and(rget_v(x2), rget_v(x0))); rset_v(x2, v128.xor(rget_v(x2), rget_v(x1))); rset_v(x1, v128.or(rget_v(x1), rget_v(x0)));
	rset_v(x0, v128.not(rget_v(x0))); rset_v(x0, v128.xor(rget_v(x0), rget_v(x2))); rset_v(x4, v128.xor(rget_v(x4), rget_v(x1)));
}

@inline function sb2_v(x0: i32, x1: i32, x2: i32, x3: i32, x4: i32): void {
	rset_v(x3, v128.not(rget_v(x3))); rset_v(x1, v128.xor(rget_v(x1), rget_v(x0))); rset_v(x4, rget_v(x0));
	rset_v(x0, v128.and(rget_v(x0), rget_v(x2))); rset_v(x0, v128.xor(rget_v(x0), rget_v(x3))); rset_v(x3, v128.or(rget_v(x3), rget_v(x4)));
	rset_v(x2, v128.xor(rget_v(x2), rget_v(x1))); rset_v(x3, v128.xor(rget_v(x3), rget_v(x1))); rset_v(x1, v128.and(rget_v(x1), rget_v(x0)));
	rset_v(x0, v128.xor(rget_v(x0), rget_v(x2))); rset_v(x2, v128.and(rget_v(x2), rget_v(x3))); rset_v(x3, v128.or(rget_v(x3), rget_v(x1)));
	rset_v(x0, v128.not(rget_v(x0))); rset_v(x3, v128.xor(rget_v(x3), rget_v(x0))); rset_v(x4, v128.xor(rget_v(x4), rget_v(x0)));
	rset_v(x0, v128.xor(rget_v(x0), rget_v(x2))); rset_v(x1, v128.or(rget_v(x1), rget_v(x2)));
}

@inline function sb3_v(x0: i32, x1: i32, x2: i32, x3: i32, x4: i32): void {
	rset_v(x4, rget_v(x1)); rset_v(x1, v128.xor(rget_v(x1), rget_v(x3))); rset_v(x3, v128.or(rget_v(x3), rget_v(x0)));
	rset_v(x4, v128.and(rget_v(x4), rget_v(x0))); rset_v(x0, v128.xor(rget_v(x0), rget_v(x2))); rset_v(x2, v128.xor(rget_v(x2), rget_v(x1)));
	rset_v(x1, v128.and(rget_v(x1), rget_v(x3))); rset_v(x2, v128.xor(rget_v(x2), rget_v(x3))); rset_v(x0, v128.or(rget_v(x0), rget_v(x4)));
	rset_v(x4, v128.xor(rget_v(x4), rget_v(x3))); rset_v(x1, v128.xor(rget_v(x1), rget_v(x0))); rset_v(x0, v128.and(rget_v(x0), rget_v(x3)));
	rset_v(x3, v128.and(rget_v(x3), rget_v(x4))); rset_v(x3, v128.xor(rget_v(x3), rget_v(x2))); rset_v(x4, v128.or(rget_v(x4), rget_v(x1)));
	rset_v(x2, v128.and(rget_v(x2), rget_v(x1))); rset_v(x4, v128.xor(rget_v(x4), rget_v(x3))); rset_v(x0, v128.xor(rget_v(x0), rget_v(x3)));
	rset_v(x3, v128.xor(rget_v(x3), rget_v(x2)));
}

@inline function sb4_v(x0: i32, x1: i32, x2: i32, x3: i32, x4: i32): void {
	rset_v(x4, rget_v(x3)); rset_v(x3, v128.and(rget_v(x3), rget_v(x0))); rset_v(x0, v128.xor(rget_v(x0), rget_v(x4)));
	rset_v(x3, v128.xor(rget_v(x3), rget_v(x2))); rset_v(x2, v128.or(rget_v(x2), rget_v(x4))); rset_v(x0, v128.xor(rget_v(x0), rget_v(x1)));
	rset_v(x4, v128.xor(rget_v(x4), rget_v(x3))); rset_v(x2, v128.or(rget_v(x2), rget_v(x0))); rset_v(x2, v128.xor(rget_v(x2), rget_v(x1)));
	rset_v(x1, v128.and(rget_v(x1), rget_v(x0))); rset_v(x1, v128.xor(rget_v(x1), rget_v(x4))); rset_v(x4, v128.and(rget_v(x4), rget_v(x2)));
	rset_v(x2, v128.xor(rget_v(x2), rget_v(x3))); rset_v(x4, v128.xor(rget_v(x4), rget_v(x0))); rset_v(x3, v128.or(rget_v(x3), rget_v(x1)));
	rset_v(x1, v128.not(rget_v(x1))); rset_v(x3, v128.xor(rget_v(x3), rget_v(x0)));
}

@inline function sb5_v(x0: i32, x1: i32, x2: i32, x3: i32, x4: i32): void {
	rset_v(x4, rget_v(x1)); rset_v(x1, v128.or(rget_v(x1), rget_v(x0))); rset_v(x2, v128.xor(rget_v(x2), rget_v(x1)));
	rset_v(x3, v128.not(rget_v(x3))); rset_v(x4, v128.xor(rget_v(x4), rget_v(x0))); rset_v(x0, v128.xor(rget_v(x0), rget_v(x2)));
	rset_v(x1, v128.and(rget_v(x1), rget_v(x4))); rset_v(x4, v128.or(rget_v(x4), rget_v(x3))); rset_v(x4, v128.xor(rget_v(x4), rget_v(x0)));
	rset_v(x0, v128.and(rget_v(x0), rget_v(x3))); rset_v(x1, v128.xor(rget_v(x1), rget_v(x3))); rset_v(x3, v128.xor(rget_v(x3), rget_v(x2)));
	rset_v(x0, v128.xor(rget_v(x0), rget_v(x1))); rset_v(x2, v128.and(rget_v(x2), rget_v(x4))); rset_v(x1, v128.xor(rget_v(x1), rget_v(x2)));
	rset_v(x2, v128.and(rget_v(x2), rget_v(x0))); rset_v(x3, v128.xor(rget_v(x3), rget_v(x2)));
}

@inline function sb6_v(x0: i32, x1: i32, x2: i32, x3: i32, x4: i32): void {
	rset_v(x4, rget_v(x1)); rset_v(x3, v128.xor(rget_v(x3), rget_v(x0))); rset_v(x1, v128.xor(rget_v(x1), rget_v(x2)));
	rset_v(x2, v128.xor(rget_v(x2), rget_v(x0))); rset_v(x0, v128.and(rget_v(x0), rget_v(x3))); rset_v(x1, v128.or(rget_v(x1), rget_v(x3)));
	rset_v(x4, v128.not(rget_v(x4))); rset_v(x0, v128.xor(rget_v(x0), rget_v(x1))); rset_v(x1, v128.xor(rget_v(x1), rget_v(x2)));
	rset_v(x3, v128.xor(rget_v(x3), rget_v(x4))); rset_v(x4, v128.xor(rget_v(x4), rget_v(x0))); rset_v(x2, v128.and(rget_v(x2), rget_v(x0)));
	rset_v(x4, v128.xor(rget_v(x4), rget_v(x1))); rset_v(x2, v128.xor(rget_v(x2), rget_v(x3))); rset_v(x3, v128.and(rget_v(x3), rget_v(x1)));
	rset_v(x3, v128.xor(rget_v(x3), rget_v(x0))); rset_v(x1, v128.xor(rget_v(x1), rget_v(x2)));
}

@inline function sb7_v(x0: i32, x1: i32, x2: i32, x3: i32, x4: i32): void {
	rset_v(x1, v128.not(rget_v(x1))); rset_v(x4, rget_v(x1)); rset_v(x0, v128.not(rget_v(x0))); rset_v(x1, v128.and(rget_v(x1), rget_v(x2)));
	rset_v(x1, v128.xor(rget_v(x1), rget_v(x3))); rset_v(x3, v128.or(rget_v(x3), rget_v(x4))); rset_v(x4, v128.xor(rget_v(x4), rget_v(x2)));
	rset_v(x2, v128.xor(rget_v(x2), rget_v(x3))); rset_v(x3, v128.xor(rget_v(x3), rget_v(x0))); rset_v(x0, v128.or(rget_v(x0), rget_v(x1)));
	rset_v(x2, v128.and(rget_v(x2), rget_v(x0))); rset_v(x0, v128.xor(rget_v(x0), rget_v(x4))); rset_v(x4, v128.xor(rget_v(x4), rget_v(x3)));
	rset_v(x3, v128.and(rget_v(x3), rget_v(x0))); rset_v(x4, v128.xor(rget_v(x4), rget_v(x1))); rset_v(x2, v128.xor(rget_v(x2), rget_v(x4)));
	rset_v(x3, v128.xor(rget_v(x3), rget_v(x1))); rset_v(x4, v128.or(rget_v(x4), rget_v(x0))); rset_v(x4, v128.xor(rget_v(x4), rget_v(x1)));
}

// ── Inverse S-boxes (v128) ──────────────────────────────────────────────────

@inline function si0_v(x0: i32, x1: i32, x2: i32, x3: i32, x4: i32): void {
	rset_v(x4, rget_v(x3)); rset_v(x1, v128.xor(rget_v(x1), rget_v(x0))); rset_v(x3, v128.or(rget_v(x3), rget_v(x1)));
	rset_v(x4, v128.xor(rget_v(x4), rget_v(x1))); rset_v(x0, v128.not(rget_v(x0))); rset_v(x2, v128.xor(rget_v(x2), rget_v(x3)));
	rset_v(x3, v128.xor(rget_v(x3), rget_v(x0))); rset_v(x0, v128.and(rget_v(x0), rget_v(x1))); rset_v(x0, v128.xor(rget_v(x0), rget_v(x2)));
	rset_v(x2, v128.and(rget_v(x2), rget_v(x3))); rset_v(x3, v128.xor(rget_v(x3), rget_v(x4))); rset_v(x2, v128.xor(rget_v(x2), rget_v(x3)));
	rset_v(x1, v128.xor(rget_v(x1), rget_v(x3))); rset_v(x3, v128.and(rget_v(x3), rget_v(x0))); rset_v(x1, v128.xor(rget_v(x1), rget_v(x0)));
	rset_v(x0, v128.xor(rget_v(x0), rget_v(x2))); rset_v(x4, v128.xor(rget_v(x4), rget_v(x3)));
}

@inline function si1_v(x0: i32, x1: i32, x2: i32, x3: i32, x4: i32): void {
	rset_v(x1, v128.xor(rget_v(x1), rget_v(x3))); rset_v(x4, rget_v(x0)); rset_v(x0, v128.xor(rget_v(x0), rget_v(x2)));
	rset_v(x2, v128.not(rget_v(x2))); rset_v(x4, v128.or(rget_v(x4), rget_v(x1))); rset_v(x4, v128.xor(rget_v(x4), rget_v(x3)));
	rset_v(x3, v128.and(rget_v(x3), rget_v(x1))); rset_v(x1, v128.xor(rget_v(x1), rget_v(x2))); rset_v(x2, v128.and(rget_v(x2), rget_v(x4)));
	rset_v(x4, v128.xor(rget_v(x4), rget_v(x1))); rset_v(x1, v128.or(rget_v(x1), rget_v(x3))); rset_v(x3, v128.xor(rget_v(x3), rget_v(x0)));
	rset_v(x2, v128.xor(rget_v(x2), rget_v(x0))); rset_v(x0, v128.or(rget_v(x0), rget_v(x4))); rset_v(x2, v128.xor(rget_v(x2), rget_v(x4)));
	rset_v(x1, v128.xor(rget_v(x1), rget_v(x0))); rset_v(x4, v128.xor(rget_v(x4), rget_v(x1)));
}

@inline function si2_v(x0: i32, x1: i32, x2: i32, x3: i32, x4: i32): void {
	rset_v(x2, v128.xor(rget_v(x2), rget_v(x1))); rset_v(x4, rget_v(x3)); rset_v(x3, v128.not(rget_v(x3)));
	rset_v(x3, v128.or(rget_v(x3), rget_v(x2))); rset_v(x2, v128.xor(rget_v(x2), rget_v(x4))); rset_v(x4, v128.xor(rget_v(x4), rget_v(x0)));
	rset_v(x3, v128.xor(rget_v(x3), rget_v(x1))); rset_v(x1, v128.or(rget_v(x1), rget_v(x2))); rset_v(x2, v128.xor(rget_v(x2), rget_v(x0)));
	rset_v(x1, v128.xor(rget_v(x1), rget_v(x4))); rset_v(x4, v128.or(rget_v(x4), rget_v(x3))); rset_v(x2, v128.xor(rget_v(x2), rget_v(x3)));
	rset_v(x4, v128.xor(rget_v(x4), rget_v(x2))); rset_v(x2, v128.and(rget_v(x2), rget_v(x1))); rset_v(x2, v128.xor(rget_v(x2), rget_v(x3)));
	rset_v(x3, v128.xor(rget_v(x3), rget_v(x4))); rset_v(x4, v128.xor(rget_v(x4), rget_v(x0)));
}

@inline function si3_v(x0: i32, x1: i32, x2: i32, x3: i32, x4: i32): void {
	rset_v(x2, v128.xor(rget_v(x2), rget_v(x1))); rset_v(x4, rget_v(x1)); rset_v(x1, v128.and(rget_v(x1), rget_v(x2)));
	rset_v(x1, v128.xor(rget_v(x1), rget_v(x0))); rset_v(x0, v128.or(rget_v(x0), rget_v(x4))); rset_v(x4, v128.xor(rget_v(x4), rget_v(x3)));
	rset_v(x0, v128.xor(rget_v(x0), rget_v(x3))); rset_v(x3, v128.or(rget_v(x3), rget_v(x1))); rset_v(x1, v128.xor(rget_v(x1), rget_v(x2)));
	rset_v(x1, v128.xor(rget_v(x1), rget_v(x3))); rset_v(x0, v128.xor(rget_v(x0), rget_v(x2))); rset_v(x2, v128.xor(rget_v(x2), rget_v(x3)));
	rset_v(x3, v128.and(rget_v(x3), rget_v(x1))); rset_v(x1, v128.xor(rget_v(x1), rget_v(x0))); rset_v(x0, v128.and(rget_v(x0), rget_v(x2)));
	rset_v(x4, v128.xor(rget_v(x4), rget_v(x3))); rset_v(x3, v128.xor(rget_v(x3), rget_v(x0))); rset_v(x0, v128.xor(rget_v(x0), rget_v(x1)));
}

@inline function si4_v(x0: i32, x1: i32, x2: i32, x3: i32, x4: i32): void {
	rset_v(x2, v128.xor(rget_v(x2), rget_v(x3))); rset_v(x4, rget_v(x0)); rset_v(x0, v128.and(rget_v(x0), rget_v(x1)));
	rset_v(x0, v128.xor(rget_v(x0), rget_v(x2))); rset_v(x2, v128.or(rget_v(x2), rget_v(x3))); rset_v(x4, v128.not(rget_v(x4)));
	rset_v(x1, v128.xor(rget_v(x1), rget_v(x0))); rset_v(x0, v128.xor(rget_v(x0), rget_v(x2))); rset_v(x2, v128.and(rget_v(x2), rget_v(x4)));
	rset_v(x2, v128.xor(rget_v(x2), rget_v(x0))); rset_v(x0, v128.or(rget_v(x0), rget_v(x4))); rset_v(x0, v128.xor(rget_v(x0), rget_v(x3)));
	rset_v(x3, v128.and(rget_v(x3), rget_v(x2))); rset_v(x4, v128.xor(rget_v(x4), rget_v(x3))); rset_v(x3, v128.xor(rget_v(x3), rget_v(x1)));
	rset_v(x1, v128.and(rget_v(x1), rget_v(x0))); rset_v(x4, v128.xor(rget_v(x4), rget_v(x1))); rset_v(x0, v128.xor(rget_v(x0), rget_v(x3)));
}

@inline function si5_v(x0: i32, x1: i32, x2: i32, x3: i32, x4: i32): void {
	rset_v(x4, rget_v(x1)); rset_v(x1, v128.or(rget_v(x1), rget_v(x2))); rset_v(x2, v128.xor(rget_v(x2), rget_v(x4)));
	rset_v(x1, v128.xor(rget_v(x1), rget_v(x3))); rset_v(x3, v128.and(rget_v(x3), rget_v(x4))); rset_v(x2, v128.xor(rget_v(x2), rget_v(x3)));
	rset_v(x3, v128.or(rget_v(x3), rget_v(x0))); rset_v(x0, v128.not(rget_v(x0))); rset_v(x3, v128.xor(rget_v(x3), rget_v(x2)));
	rset_v(x2, v128.or(rget_v(x2), rget_v(x0))); rset_v(x4, v128.xor(rget_v(x4), rget_v(x1))); rset_v(x2, v128.xor(rget_v(x2), rget_v(x4)));
	rset_v(x4, v128.and(rget_v(x4), rget_v(x0))); rset_v(x0, v128.xor(rget_v(x0), rget_v(x1))); rset_v(x1, v128.xor(rget_v(x1), rget_v(x3)));
	rset_v(x0, v128.and(rget_v(x0), rget_v(x2))); rset_v(x2, v128.xor(rget_v(x2), rget_v(x3))); rset_v(x0, v128.xor(rget_v(x0), rget_v(x2)));
	rset_v(x2, v128.xor(rget_v(x2), rget_v(x4))); rset_v(x4, v128.xor(rget_v(x4), rget_v(x3)));
}

@inline function si6_v(x0: i32, x1: i32, x2: i32, x3: i32, x4: i32): void {
	rset_v(x0, v128.xor(rget_v(x0), rget_v(x2))); rset_v(x4, rget_v(x0)); rset_v(x0, v128.and(rget_v(x0), rget_v(x3)));
	rset_v(x2, v128.xor(rget_v(x2), rget_v(x3))); rset_v(x0, v128.xor(rget_v(x0), rget_v(x2))); rset_v(x3, v128.xor(rget_v(x3), rget_v(x1)));
	rset_v(x2, v128.or(rget_v(x2), rget_v(x4))); rset_v(x2, v128.xor(rget_v(x2), rget_v(x3))); rset_v(x3, v128.and(rget_v(x3), rget_v(x0)));
	rset_v(x0, v128.not(rget_v(x0))); rset_v(x3, v128.xor(rget_v(x3), rget_v(x1))); rset_v(x1, v128.and(rget_v(x1), rget_v(x2)));
	rset_v(x4, v128.xor(rget_v(x4), rget_v(x0))); rset_v(x3, v128.xor(rget_v(x3), rget_v(x4))); rset_v(x4, v128.xor(rget_v(x4), rget_v(x2)));
	rset_v(x0, v128.xor(rget_v(x0), rget_v(x1))); rset_v(x2, v128.xor(rget_v(x2), rget_v(x0)));
}

@inline function si7_v(x0: i32, x1: i32, x2: i32, x3: i32, x4: i32): void {
	rset_v(x4, rget_v(x3)); rset_v(x3, v128.and(rget_v(x3), rget_v(x0))); rset_v(x0, v128.xor(rget_v(x0), rget_v(x2)));
	rset_v(x2, v128.or(rget_v(x2), rget_v(x4))); rset_v(x4, v128.xor(rget_v(x4), rget_v(x1))); rset_v(x0, v128.not(rget_v(x0)));
	rset_v(x1, v128.or(rget_v(x1), rget_v(x3))); rset_v(x4, v128.xor(rget_v(x4), rget_v(x0))); rset_v(x0, v128.and(rget_v(x0), rget_v(x2)));
	rset_v(x0, v128.xor(rget_v(x0), rget_v(x1))); rset_v(x1, v128.and(rget_v(x1), rget_v(x2))); rset_v(x3, v128.xor(rget_v(x3), rget_v(x2)));
	rset_v(x4, v128.xor(rget_v(x4), rget_v(x3))); rset_v(x2, v128.and(rget_v(x2), rget_v(x3))); rset_v(x3, v128.or(rget_v(x3), rget_v(x0)));
	rset_v(x1, v128.xor(rget_v(x1), rget_v(x4))); rset_v(x3, v128.xor(rget_v(x3), rget_v(x4))); rset_v(x4, v128.and(rget_v(x4), rget_v(x0)));
	rset_v(x4, v128.xor(rget_v(x4), rget_v(x2)));
}

// ── Key XOR (v128) — splat scalar subkey to all 4 lanes ────────────────────

@inline function keyXor_v(a: i32, b: i32, c: i32, d: i32, i: i32): void {
	rset_v(a, v128.xor(rget_v(a), i32x4.splat(load<i32>(SUBKEY_OFFSET + (4 * i + 0) * 4))))
	rset_v(b, v128.xor(rget_v(b), i32x4.splat(load<i32>(SUBKEY_OFFSET + (4 * i + 1) * 4))))
	rset_v(c, v128.xor(rget_v(c), i32x4.splat(load<i32>(SUBKEY_OFFSET + (4 * i + 2) * 4))))
	rset_v(d, v128.xor(rget_v(d), i32x4.splat(load<i32>(SUBKEY_OFFSET + (4 * i + 3) * 4))))
}

// ── Linear transform + key XOR (v128, encrypt) ─────────────────────────────
// Rotation amounts: 13, 3, 1, 7, 5, 22 — from Serpent spec via serpent.ts lk()

@inline function lk_v(a: i32, b: i32, c: i32, d: i32, e: i32, i: i32): void {
	rset_v(a, v128.or(i32x4.shl(rget_v(a), 13), i32x4.shr_u(rget_v(a), 19)))
	rset_v(c, v128.or(i32x4.shl(rget_v(c), 3), i32x4.shr_u(rget_v(c), 29)))
	rset_v(b, v128.xor(rget_v(b), rget_v(a)))
	rset_v(e, i32x4.shl(rget_v(a), 3))
	rset_v(d, v128.xor(rget_v(d), rget_v(c)))
	rset_v(b, v128.xor(rget_v(b), rget_v(c)))
	rset_v(b, v128.or(i32x4.shl(rget_v(b), 1), i32x4.shr_u(rget_v(b), 31)))
	rset_v(d, v128.xor(rget_v(d), rget_v(e)))
	rset_v(d, v128.or(i32x4.shl(rget_v(d), 7), i32x4.shr_u(rget_v(d), 25)))
	rset_v(e, rget_v(b))
	rset_v(a, v128.xor(rget_v(a), rget_v(b)))
	rset_v(e, i32x4.shl(rget_v(e), 7))
	rset_v(c, v128.xor(rget_v(c), rget_v(d)))
	rset_v(a, v128.xor(rget_v(a), rget_v(d)))
	rset_v(c, v128.xor(rget_v(c), rget_v(e)))
	rset_v(d, v128.xor(rget_v(d), i32x4.splat(load<i32>(SUBKEY_OFFSET + (4 * i + 3) * 4))))
	rset_v(b, v128.xor(rget_v(b), i32x4.splat(load<i32>(SUBKEY_OFFSET + (4 * i + 1) * 4))))
	rset_v(a, v128.or(i32x4.shl(rget_v(a), 5), i32x4.shr_u(rget_v(a), 27)))
	rset_v(c, v128.or(i32x4.shl(rget_v(c), 22), i32x4.shr_u(rget_v(c), 10)))
	rset_v(a, v128.xor(rget_v(a), i32x4.splat(load<i32>(SUBKEY_OFFSET + (4 * i + 0) * 4))))
	rset_v(c, v128.xor(rget_v(c), i32x4.splat(load<i32>(SUBKEY_OFFSET + (4 * i + 2) * 4))))
}

// ── Inverse linear transform + key XOR (v128, decrypt) ──────────────────────
// Rotation amounts: 27, 10, 31, 25, 19, 29 — from Serpent spec via serpent.ts kl()

@inline function kl_v(a: i32, b: i32, c: i32, d: i32, e: i32, i: i32): void {
	rset_v(a, v128.xor(rget_v(a), i32x4.splat(load<i32>(SUBKEY_OFFSET + (4 * i + 0) * 4))))
	rset_v(b, v128.xor(rget_v(b), i32x4.splat(load<i32>(SUBKEY_OFFSET + (4 * i + 1) * 4))))
	rset_v(c, v128.xor(rget_v(c), i32x4.splat(load<i32>(SUBKEY_OFFSET + (4 * i + 2) * 4))))
	rset_v(d, v128.xor(rget_v(d), i32x4.splat(load<i32>(SUBKEY_OFFSET + (4 * i + 3) * 4))))
	rset_v(a, v128.or(i32x4.shl(rget_v(a), 27), i32x4.shr_u(rget_v(a), 5)))
	rset_v(c, v128.or(i32x4.shl(rget_v(c), 10), i32x4.shr_u(rget_v(c), 22)))
	rset_v(e, rget_v(b))
	rset_v(c, v128.xor(rget_v(c), rget_v(d)))
	rset_v(a, v128.xor(rget_v(a), rget_v(d)))
	rset_v(e, i32x4.shl(rget_v(e), 7))
	rset_v(a, v128.xor(rget_v(a), rget_v(b)))
	rset_v(b, v128.or(i32x4.shl(rget_v(b), 31), i32x4.shr_u(rget_v(b), 1)))
	rset_v(c, v128.xor(rget_v(c), rget_v(e)))
	rset_v(d, v128.or(i32x4.shl(rget_v(d), 25), i32x4.shr_u(rget_v(d), 7)))
	rset_v(e, i32x4.shl(rget_v(a), 3))
	rset_v(b, v128.xor(rget_v(b), rget_v(a)))
	rset_v(d, v128.xor(rget_v(d), rget_v(e)))
	rset_v(a, v128.or(i32x4.shl(rget_v(a), 19), i32x4.shr_u(rget_v(a), 13)))
	rset_v(b, v128.xor(rget_v(b), rget_v(c)))
	rset_v(d, v128.xor(rget_v(d), rget_v(c)))
	rset_v(c, v128.or(i32x4.shl(rget_v(c), 29), i32x4.shr_u(rget_v(c), 3)))
}

// ── Encrypt 4 blocks (v128) ─────────────────────────────────────────────────
// Caller loads 4 interleaved plaintext blocks into v128 registers [0..3].
// lane[k] of register r[w] = word w of block k  (k = 0..3).
// Result is left in v128 registers [0..3] for caller to deinterleave.
export function encryptBlock_simd_4x(): void {
	keyXor_v(0, 1, 2, 3, 0) // K(0)

	// Round 0: sb0_v
	sb0_v(0, 1, 2, 3, 4)
	lk_v(2, 1, 3, 0, 4, 1)

	// Round 1: sb1_v
	sb1_v(2, 1, 3, 0, 4)
	lk_v(4, 3, 0, 2, 1, 2)

	// Round 2: sb2_v
	sb2_v(4, 3, 0, 2, 1)
	lk_v(1, 3, 4, 2, 0, 3)

	// Round 3: sb3_v
	sb3_v(1, 3, 4, 2, 0)
	lk_v(2, 0, 3, 1, 4, 4)

	// Round 4: sb4_v
	sb4_v(2, 0, 3, 1, 4)
	lk_v(0, 3, 1, 4, 2, 5)

	// Round 5: sb5_v
	sb5_v(0, 3, 1, 4, 2)
	lk_v(2, 0, 3, 4, 1, 6)

	// Round 6: sb6_v
	sb6_v(2, 0, 3, 4, 1)
	lk_v(3, 1, 0, 4, 2, 7)

	// Round 7: sb7_v
	sb7_v(3, 1, 0, 4, 2)
	lk_v(2, 0, 4, 3, 1, 8)

	// Round 8: sb0_v
	sb0_v(2, 0, 4, 3, 1)
	lk_v(4, 0, 3, 2, 1, 9)

	// Round 9: sb1_v
	sb1_v(4, 0, 3, 2, 1)
	lk_v(1, 3, 2, 4, 0, 10)

	// Round 10: sb2_v
	sb2_v(1, 3, 2, 4, 0)
	lk_v(0, 3, 1, 4, 2, 11)

	// Round 11: sb3_v
	sb3_v(0, 3, 1, 4, 2)
	lk_v(4, 2, 3, 0, 1, 12)

	// Round 12: sb4_v
	sb4_v(4, 2, 3, 0, 1)
	lk_v(2, 3, 0, 1, 4, 13)

	// Round 13: sb5_v
	sb5_v(2, 3, 0, 1, 4)
	lk_v(4, 2, 3, 1, 0, 14)

	// Round 14: sb6_v
	sb6_v(4, 2, 3, 1, 0)
	lk_v(3, 0, 2, 1, 4, 15)

	// Round 15: sb7_v
	sb7_v(3, 0, 2, 1, 4)
	lk_v(4, 2, 1, 3, 0, 16)

	// Round 16: sb0_v
	sb0_v(4, 2, 1, 3, 0)
	lk_v(1, 2, 3, 4, 0, 17)

	// Round 17: sb1_v
	sb1_v(1, 2, 3, 4, 0)
	lk_v(0, 3, 4, 1, 2, 18)

	// Round 18: sb2_v
	sb2_v(0, 3, 4, 1, 2)
	lk_v(2, 3, 0, 1, 4, 19)

	// Round 19: sb3_v
	sb3_v(2, 3, 0, 1, 4)
	lk_v(1, 4, 3, 2, 0, 20)

	// Round 20: sb4_v
	sb4_v(1, 4, 3, 2, 0)
	lk_v(4, 3, 2, 0, 1, 21)

	// Round 21: sb5_v
	sb5_v(4, 3, 2, 0, 1)
	lk_v(1, 4, 3, 0, 2, 22)

	// Round 22: sb6_v
	sb6_v(1, 4, 3, 0, 2)
	lk_v(3, 2, 4, 0, 1, 23)

	// Round 23: sb7_v
	sb7_v(3, 2, 4, 0, 1)
	lk_v(1, 4, 0, 3, 2, 24)

	// Round 24: sb0_v
	sb0_v(1, 4, 0, 3, 2)
	lk_v(0, 4, 3, 1, 2, 25)

	// Round 25: sb1_v
	sb1_v(0, 4, 3, 1, 2)
	lk_v(2, 3, 1, 0, 4, 26)

	// Round 26: sb2_v
	sb2_v(2, 3, 1, 0, 4)
	lk_v(4, 3, 2, 0, 1, 27)

	// Round 27: sb3_v
	sb3_v(4, 3, 2, 0, 1)
	lk_v(0, 1, 3, 4, 2, 28)

	// Round 28: sb4_v
	sb4_v(0, 1, 3, 4, 2)
	lk_v(1, 3, 4, 2, 0, 29)

	// Round 29: sb5_v
	sb5_v(1, 3, 4, 2, 0)
	lk_v(0, 1, 3, 2, 4, 30)

	// Round 30: sb6_v
	sb6_v(0, 1, 3, 2, 4)
	lk_v(3, 4, 1, 2, 0, 31)

	// Round 31 (final — no linear transform)
	sb7_v(3, 4, 1, 2, 0)

	keyXor_v(0, 1, 2, 3, 32) // K(32)
}

// ── Decrypt 4 blocks (v128) ─────────────────────────────────────────────────
// Same interleaved layout as encrypt. Result in v128 registers.
// Note: output registers are [4,1,3,2] not [0,1,2,3] — matches scalar decrypt.
export function decryptBlock_simd_4x(): void {
	keyXor_v(0, 1, 2, 3, 32) // K(32)

	// Round 0: si7_v
	si7_v(0, 1, 2, 3, 4)
	kl_v(1, 3, 0, 4, 2, 31)

	// Round 1: si6_v
	si6_v(1, 3, 0, 4, 2)
	kl_v(0, 2, 4, 1, 3, 30)

	// Round 2: si5_v
	si5_v(0, 2, 4, 1, 3)
	kl_v(2, 3, 0, 4, 1, 29)

	// Round 3: si4_v
	si4_v(2, 3, 0, 4, 1)
	kl_v(2, 0, 1, 4, 3, 28)

	// Round 4: si3_v
	si3_v(2, 0, 1, 4, 3)
	kl_v(1, 2, 3, 4, 0, 27)

	// Round 5: si2_v
	si2_v(1, 2, 3, 4, 0)
	kl_v(2, 0, 4, 3, 1, 26)

	// Round 6: si1_v
	si1_v(2, 0, 4, 3, 1)
	kl_v(1, 0, 4, 3, 2, 25)

	// Round 7: si0_v
	si0_v(1, 0, 4, 3, 2)
	kl_v(4, 2, 0, 1, 3, 24)

	// Round 8: si7_v
	si7_v(4, 2, 0, 1, 3)
	kl_v(2, 1, 4, 3, 0, 23)

	// Round 9: si6_v
	si6_v(2, 1, 4, 3, 0)
	kl_v(4, 0, 3, 2, 1, 22)

	// Round 10: si5_v
	si5_v(4, 0, 3, 2, 1)
	kl_v(0, 1, 4, 3, 2, 21)

	// Round 11: si4_v
	si4_v(0, 1, 4, 3, 2)
	kl_v(0, 4, 2, 3, 1, 20)

	// Round 12: si3_v
	si3_v(0, 4, 2, 3, 1)
	kl_v(2, 0, 1, 3, 4, 19)

	// Round 13: si2_v
	si2_v(2, 0, 1, 3, 4)
	kl_v(0, 4, 3, 1, 2, 18)

	// Round 14: si1_v
	si1_v(0, 4, 3, 1, 2)
	kl_v(2, 4, 3, 1, 0, 17)

	// Round 15: si0_v
	si0_v(2, 4, 3, 1, 0)
	kl_v(3, 0, 4, 2, 1, 16)

	// Round 16: si7_v
	si7_v(3, 0, 4, 2, 1)
	kl_v(0, 2, 3, 1, 4, 15)

	// Round 17: si6_v
	si6_v(0, 2, 3, 1, 4)
	kl_v(3, 4, 1, 0, 2, 14)

	// Round 18: si5_v
	si5_v(3, 4, 1, 0, 2)
	kl_v(4, 2, 3, 1, 0, 13)

	// Round 19: si4_v
	si4_v(4, 2, 3, 1, 0)
	kl_v(4, 3, 0, 1, 2, 12)

	// Round 20: si3_v
	si3_v(4, 3, 0, 1, 2)
	kl_v(0, 4, 2, 1, 3, 11)

	// Round 21: si2_v
	si2_v(0, 4, 2, 1, 3)
	kl_v(4, 3, 1, 2, 0, 10)

	// Round 22: si1_v
	si1_v(4, 3, 1, 2, 0)
	kl_v(0, 3, 1, 2, 4, 9)

	// Round 23: si0_v
	si0_v(0, 3, 1, 2, 4)
	kl_v(1, 4, 3, 0, 2, 8)

	// Round 24: si7_v
	si7_v(1, 4, 3, 0, 2)
	kl_v(4, 0, 1, 2, 3, 7)

	// Round 25: si6_v
	si6_v(4, 0, 1, 2, 3)
	kl_v(1, 3, 2, 4, 0, 6)

	// Round 26: si5_v
	si5_v(1, 3, 2, 4, 0)
	kl_v(3, 0, 1, 2, 4, 5)

	// Round 27: si4_v
	si4_v(3, 0, 1, 2, 4)
	kl_v(3, 1, 4, 2, 0, 4)

	// Round 28: si3_v
	si3_v(3, 1, 4, 2, 0)
	kl_v(4, 3, 0, 2, 1, 3)

	// Round 29: si2_v
	si2_v(4, 3, 0, 2, 1)
	kl_v(3, 1, 2, 0, 4, 2)

	// Round 30: si1_v
	si1_v(3, 1, 2, 0, 4)
	kl_v(4, 1, 2, 0, 3, 1)

	// Round 31 (final — no inverse linear transform)
	si0_v(4, 1, 2, 0, 3)

	// K(0): final key XOR — slots (2,3,1,4), NOT (0,1,2,3)
	keyXor_v(2, 3, 1, 4, 0)
}
