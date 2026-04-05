//                  ▄▄▄▄▄▄▄▄▄▄
//           ▄████████████████████▄▄          ▒  ▄▀▀ ▒ ▒ █ ▄▀▄ ▀█▀ █ ▒ ▄▀▄ █▀▄
//        ▄██████████████████████ ▀████▄      ▓  ▓▀  ▓ ▓ ▓ ▓▄▓  ▓  ▓▀▓ ▓▄▓ ▓ ▓
//      ▄█████████▀▀▀     ▀███████▄▄███████▌  ▀▄ ▀▄▄ ▀▄▀ ▒ ▒ ▒  ▒ █ ▒ ▒ ▒ █
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
// src/asm/kyber/verify.ts
//
// ML-KEM (Kyber) — constant-time byte comparison and conditional move.
// FIPS 203 §6.3 — used in KEM Decapsulate to prevent decryption oracle attacks.
// Reference: pq-crystals/kyber main ref/verify.c.
//
// Security note: no early return, no branch on secret-derived values.
// ct_verify uses XOR-accumulate only. ct_cmov uses mask-and-XOR only.

/**
 * Compare two byte arrays in constant time. FIPS 203 §6.3.
 * Returns 0 if equal, 1 if any byte differs.
 * XOR-accumulate with no early return — no branch on secret data.
 * @param aOffset first byte array offset
 * @param bOffset second byte array offset
 * @param len     array length in bytes
 */
export function ct_verify(aOffset: i32, bOffset: i32, len: i32): i32 {
	let r: u8 = 0;
	for (let i: i32 = 0; i < len; i++) {
		r |= load<u8>(aOffset + i) ^ load<u8>(bOffset + i);
	}
	// (-(u64)r) >> 63: non-zero r gives 1, zero r gives 0
	return <i32>(<u64>-<u64>r >> 63);
}

/**
 * Conditional move: if b==1, copy x to r; if b==0, no-op. FIPS 203 §6.3.
 * Mask-and-XOR pattern — no branch on b or data.
 * @param rOffset destination byte array offset
 * @param xOffset source byte array offset
 * @param len     array length in bytes
 * @param b       condition: must be 0 or 1
 */
export function ct_cmov(rOffset: i32, xOffset: i32, len: i32, b: i32): void {
	// mask = -b: 0xFF...FF if b==1, 0x00...00 if b==0
	const mask: u8 = <u8>-b;
	for (let i: i32 = 0; i < len; i++) {
		const ri: u8 = load<u8>(rOffset + i);
		const xi: u8 = load<u8>(xOffset + i);
		store<u8>(rOffset + i, ri ^ (mask & (ri ^ xi)));
	}
}
