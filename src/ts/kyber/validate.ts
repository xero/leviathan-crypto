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
// src/ts/kyber/validate.ts
//
// ML-KEM key validation — FIPS 203 §7.2 and §7.3.

import type { KyberExports, Sha3Exports } from './types.js';
import type { KyberParams } from './params.js';
import { sha3_256Hash } from './indcpa.js';
import { constantTimeEqual } from '../utils.js';

/**
 * Encapsulation key check — FIPS 203 §7.2 (EncapsulationKeyCheck).
 *
 * 1. Length gate: ek.length must equal params.ekBytes.
 * 2. Decode the polyvec portion via ByteDecode₁₂ (polyvec_frombytes). The
 *    decoded coefficients are raw 12-bit values in [0, 4095] — frombytes
 *    does not reduce mod q.
 * 3. Modulus scan: every coefficient must satisfy c < Q = 3329.
 *
 * Returns true iff both gates pass. The seed ρ (final 32 bytes of ek) is
 * not checked; any 32-byte value is a valid ρ per FIPS 203.
 */
export function checkEncapsulationKey(
	kx: KyberExports,
	params: KyberParams,
	ek: Uint8Array,
): boolean {
	if (ek.length !== params.ekBytes) return false;

	const { k } = params;
	const kyberMem = new Uint8Array(kx.memory.buffer);
	const pkOff   = kx.getPkOffset();
	const pvecOff = kx.getPolyvecSlot0();

	kyberMem.set(ek.subarray(0, k * 384), pkOff);
	kx.polyvec_frombytes(pvecOff, pkOff, k);
	return kx.polyvec_modulus_check(pvecOff, k) === 0;
}

/**
 * Decapsulation key check — FIPS 203 §7.3 (DecapsulationKeyCheck).
 *
 * 1. Length check: dk.length == params.dkBytes
 * 2. Extract embedded ek and H(ek), verify SHA3-256(ek) matches stored H
 * 3. Also run checkEncapsulationKey on the embedded ek
 */
export function checkDecapsulationKey(
	kx: KyberExports,
	sx: Sha3Exports,
	params: KyberParams,
	dk: Uint8Array,
): boolean {
	if (dk.length !== params.dkBytes) return false;

	const { skCpaBytes, ekBytes } = params;
	const ek = dk.slice(skCpaBytes, skCpaBytes + ekBytes);
	const h  = dk.slice(skCpaBytes + ekBytes, skCpaBytes + ekBytes + 32);

	try {
		const hComputed = sha3_256Hash(sx, ek);
		if (!constantTimeEqual(hComputed, h)) return false;
		return checkEncapsulationKey(kx, params, ek);
	} finally {
		sx.wipeBuffers();
	}
}
