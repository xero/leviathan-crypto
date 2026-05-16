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
// src/ts/mldsa/sha3-helpers.ts
//
// SHAKE-driving helpers shared by ExpandA / ExpandS / keygen / sign / verify.
// All operate directly on raw Sha3Exports; no init() system involved.
//
// ML-DSA uses both SHAKE rates (FIPS 202): SHAKE128 (rate 168) for ExpandA
// and SHAKE256 (rate 136) for the rest of the scheme. The absorb path is
// rate-agnostic, keccakAbsorb consumes whatever buffer length the caller
// hands it as long as length ≤ 168 (the wider rate). One-shot SHAKE256
// helpers and the incremental SHAKE128 / SHAKE256 squeezers below cover
// every call shape ML-DSA needs.

import type { Sha3Exports } from '../kyber/types.js';

const SHAKE128_RATE = 168;
const SHAKE256_RATE = 136;

/** Absorb msg into the sponge in ≤168-byte chunks. Caller must have
 *  already invoked the appropriate Init function (shake128Init etc.). */
export function sha3Absorb(sx: Sha3Exports, msg: Uint8Array): void {
	const mem = new Uint8Array(sx.memory.buffer);
	const inOff = sx.getInputOffset();
	let pos = 0;
	while (pos < msg.length) {
		const chunk = Math.min(msg.length - pos, SHAKE128_RATE);
		mem.set(msg.subarray(pos, pos + chunk), inOff);
		sx.keccakAbsorb(chunk);
		pos += chunk;
	}
}

/** SHAKE256(msg, n), fixed-length output. Resets sha3 state. */
export function shake256Hash(sx: Sha3Exports, msg: Uint8Array, n: number): Uint8Array {
	sx.shake256Init();
	sha3Absorb(sx, msg);
	sx.shakePad();
	const sha3Mem = new Uint8Array(sx.memory.buffer);
	const outOff = sx.getOutOffset();
	const out = new Uint8Array(n);
	let pos = 0;
	while (pos < n) {
		sx.shakeSqueezeBlock();
		const take = Math.min(n - pos, SHAKE256_RATE);
		out.set(sha3Mem.subarray(outOff, outOff + take), pos);
		pos += take;
	}
	return out;
}

/** SHAKE256(p₀ ‖ p₁ ‖ … ‖ p_{n-1}, outLen). Avoids the temporary buffer
 *  callers would otherwise allocate just to concatenate fixed-size pieces.
 *  Used for keygen's H(ξ ‖ k_byte ‖ ℓ_byte, 128). */
export function shake256HashConcat(
	sx: Sha3Exports,
	parts: readonly Uint8Array[],
	outLen: number,
): Uint8Array {
	sx.shake256Init();
	for (const p of parts) sha3Absorb(sx, p);
	sx.shakePad();
	const sha3Mem = new Uint8Array(sx.memory.buffer);
	const outOff = sx.getOutOffset();
	const out = new Uint8Array(outLen);
	let pos = 0;
	while (pos < outLen) {
		sx.shakeSqueezeBlock();
		const take = Math.min(outLen - pos, SHAKE256_RATE);
		out.set(sha3Mem.subarray(outOff, outOff + take), pos);
		pos += take;
	}
	return out;
}

/**
 * Set up SHAKE128 over `seed` and return an incremental block-squeezer.
 * Each call returns the next 168-byte block as a Uint8Array view into the
 * sha3 OUT region (lifetime: until the next squeeze call). Callers copy
 * into the consuming module's XOF buffer before invoking the rejection
 * sampler. Used by ExpandA (FIPS 204 Algorithm 32, RejNTTPoly driver).
 */
export function shake128Squeezer(sx: Sha3Exports, seed: Uint8Array): {
	rate: number
	squeeze: () => Uint8Array
} {
	sx.shake128Init();
	sha3Absorb(sx, seed);
	sx.shakePad();
	const sha3Mem = new Uint8Array(sx.memory.buffer);
	const outOff = sx.getOutOffset();
	return {
		rate: SHAKE128_RATE,
		squeeze: (): Uint8Array => {
			sx.shakeSqueezeBlock();
			return sha3Mem.subarray(outOff, outOff + SHAKE128_RATE);
		},
	};
}

/**
 * Set up SHAKE256 over `seed` and return an incremental block-squeezer.
 * Same shape as shake128Squeezer with rate 136. Used by ExpandS
 * (FIPS 204 Algorithm 33, RejBoundedPoly driver).
 */
export function shake256Squeezer(sx: Sha3Exports, seed: Uint8Array): {
	rate: number
	squeeze: () => Uint8Array
} {
	sx.shake256Init();
	sha3Absorb(sx, seed);
	sx.shakePad();
	const sha3Mem = new Uint8Array(sx.memory.buffer);
	const outOff = sx.getOutOffset();
	return {
		rate: SHAKE256_RATE,
		squeeze: (): Uint8Array => {
			sx.shakeSqueezeBlock();
			return sha3Mem.subarray(outOff, outOff + SHAKE256_RATE);
		},
	};
}
